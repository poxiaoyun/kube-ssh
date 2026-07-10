package accesspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

type AccessStatusUpdater func(context.Context, *sshv1.Access) (*sshv1.Access, error)

type AccessStatusController struct {
	accesses      Store
	pods          PodLister
	secretIndexer cache.Indexer
	updateStatus  AccessStatusUpdater
	selector      *StrategySelector
	queue         workqueue.TypedRateLimitingInterface[string]
}

func NewAccessStatusController(accesses Store, pods PodLister, secretIndexer cache.Indexer, updateStatus AccessStatusUpdater) *AccessStatusController {
	return &AccessStatusController{
		accesses:      accesses,
		pods:          pods,
		secretIndexer: secretIndexer,
		updateStatus:  updateStatus,
		selector:      NewStrategySelector(),
		queue:         workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
}

func (c *AccessStatusController) Start(ctx context.Context) {
	if c == nil || c.queue == nil {
		return
	}
	c.enqueueAll(ctx)
	go func() {
		<-ctx.Done()
		c.queue.ShutDown()
	}()
	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
}

func (c *AccessStatusController) AccessEventHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if key, ok := objectKey(obj); ok {
				c.queue.Add(key)
			}
		},
		UpdateFunc: func(_, obj any) {
			if key, ok := objectKey(obj); ok {
				c.queue.Add(key)
			}
		},
	}
}

func (c *AccessStatusController) PodEventHandler() cache.ResourceEventHandlerFuncs {
	return c.enqueueAllEventHandler()
}

func (c *AccessStatusController) SecretEventHandler() cache.ResourceEventHandlerFuncs {
	return c.enqueueAllEventHandler()
}

func (c *AccessStatusController) enqueueAllEventHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) {
			c.enqueueAll(context.Background())
		},
		UpdateFunc: func(_, _ any) {
			c.enqueueAll(context.Background())
		},
		DeleteFunc: func(any) {
			c.enqueueAll(context.Background())
		},
	}
}

func (c *AccessStatusController) enqueueAll(ctx context.Context) {
	if c == nil || c.accesses == nil || c.queue == nil {
		return
	}
	accesses, err := c.accesses.List(ctx)
	if err != nil {
		slog.WarnContext(ctx, "list access objects for status failed", "err", err)
		return
	}
	for _, access := range accesses {
		c.queue.Add(accessKey(access.Namespace, access.Name))
	}
}

func (c *AccessStatusController) runWorker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *AccessStatusController) processNext(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)

	if err := c.sync(ctx, key); err != nil {
		if c.queue.NumRequeues(key) < 5 {
			c.queue.AddRateLimited(key)
			return true
		}
		slog.WarnContext(ctx, "update access status failed", "access", key, "err", err)
		c.queue.Forget(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

func (c *AccessStatusController) sync(ctx context.Context, key string) error {
	if c == nil || c.accesses == nil || c.updateStatus == nil {
		return nil
	}
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}
	access, err := c.accesses.Get(ctx, namespace, name)
	if err != nil {
		return nil
	}
	status := c.statusFor(ctx, access)
	if access.Status.ObservedGeneration == status.ObservedGeneration &&
		access.Status.SelectedBackend == status.SelectedBackend &&
		equality.Semantic.DeepEqual(access.Status.Conditions, status.Conditions) {
		return nil
	}
	updated := access.DeepCopy()
	updated.Status = status
	_, err = c.updateStatus(ctx, updated)
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *AccessStatusController) statusFor(ctx context.Context, access *sshv1.Access) sshv1.AccessStatus {
	status := sshv1.AccessStatus{
		ObservedGeneration: access.Generation,
		Conditions:         append([]metav1.Condition(nil), access.Status.Conditions...),
	}
	validStatus, validReason, validMessage := c.validateAccess(access)
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               sshv1.AccessConditionValid,
		Status:             validStatus,
		ObservedGeneration: access.Generation,
		Reason:             validReason,
		Message:            validMessage,
	})
	if validStatus != metav1.ConditionTrue {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               sshv1.AccessConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: access.Generation,
			Reason:             "Invalid",
			Message:            "Access is not valid.",
		})
		return status
	}
	if c.pods == nil {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               sshv1.AccessConditionReady,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: access.Generation,
			Reason:             "PodCacheUnavailable",
			Message:            "Pod informer cache is not available.",
		})
		return status
	}

	pods, err := c.pods.List(ctx, access.Namespace, access.Spec.Selector)
	if err != nil {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               sshv1.AccessConditionReady,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: access.Generation,
			Reason:             "ListFailed",
			Message:            err.Error(),
		})
		return status
	}
	pod, ok := c.selector.PreviewPod(access, pods)
	if !ok {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               sshv1.AccessConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: access.Generation,
			Reason:             "NoBackends",
			Message:            "Access selector matches no active Pods.",
		})
		return status
	}
	status.SelectedBackend = "pod/" + access.Namespace + "/" + pod.Name
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               sshv1.AccessConditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: access.Generation,
		Reason:             "BackendAvailable",
		Message:            "Access has at least one active Pod backend.",
	})
	return status
}

func (c *AccessStatusController) validateAccess(access *sshv1.Access) (metav1.ConditionStatus, string, string) {
	if access == nil {
		return metav1.ConditionFalse, "InvalidSpec", "Access is nil."
	}
	if !isPodAccess(access) {
		return metav1.ConditionFalse, "UnsupportedType", "External Access is not implemented by this kube-ssh version."
	}
	if len(access.Spec.Selector) == 0 {
		return metav1.ConditionFalse, "InvalidSelector", "Pod Access requires a non-empty selector."
	}
	if len(access.Spec.Credentials) == 0 {
		return metav1.ConditionFalse, "NoCredentials", "Access requires at least one credential entry."
	}
	for i, credential := range access.Spec.Credentials {
		if strings.TrimSpace(credential.Username) == "" {
			return metav1.ConditionFalse, "InvalidCredential", fmt.Sprintf("Credential at index %d requires username.", i)
		}
		if ok, reason, message := c.validateCredential(access.Namespace, i, credential); !ok {
			return metav1.ConditionFalse, reason, message
		}
	}
	return metav1.ConditionTrue, "Valid", "Access spec and referenced credentials are valid."
}

func (c *AccessStatusController) validateCredential(namespace string, index int, credential sshv1.AccessCredential) (bool, string, string) {
	hasMaterial := false
	for _, password := range credential.Passwords {
		hasMaterial = true
		if password == "" {
			return false, "InvalidCredential", fmt.Sprintf("Credential %q has an empty password token.", credential.Username)
		}
	}
	for _, key := range credential.PublicKeys {
		hasMaterial = true
		if keyFingerprint(key) == "" {
			return false, "InvalidCredential", fmt.Sprintf("Credential %q has an invalid public key.", credential.Username)
		}
	}
	for _, ref := range credential.PasswordsFrom {
		hasMaterial = true
		if ok, reason, message := c.validatePasswordSecretRef(namespace, credential.Username, ref); !ok {
			return false, reason, message
		}
	}
	for _, ref := range credential.PublicKeysFrom {
		hasMaterial = true
		if ok, reason, message := c.validatePublicKeySecretRef(namespace, credential.Username, ref); !ok {
			return false, reason, message
		}
	}
	if !hasMaterial {
		return false, "InvalidCredential", fmt.Sprintf("Credential %d/%q has no password or public key material.", index, credential.Username)
	}
	return true, "", ""
}

func (c *AccessStatusController) validatePasswordSecretRef(namespace, username string, ref sshv1.LocalSecretKeyRef) (bool, string, string) {
	value, ok, reason, message := c.secretValue(namespace, username, ref)
	if !ok {
		return false, reason, message
	}
	if len(splitSecretLines(string(value))) == 0 {
		return false, "InvalidSecretRef", fmt.Sprintf("Credential %q password secret %s/%s key %q contains no tokens.", username, namespace, ref.Name, ref.Key)
	}
	return true, "", ""
}

func (c *AccessStatusController) validatePublicKeySecretRef(namespace, username string, ref sshv1.LocalSecretKeyRef) (bool, string, string) {
	value, ok, reason, message := c.secretValue(namespace, username, ref)
	if !ok {
		return false, reason, message
	}
	lines := splitSecretLines(string(value))
	if len(lines) == 0 {
		return false, "InvalidSecretRef", fmt.Sprintf("Credential %q public key secret %s/%s key %q contains no keys.", username, namespace, ref.Name, ref.Key)
	}
	for _, line := range lines {
		if keyFingerprint(line) == "" {
			return false, "InvalidSecretRef", fmt.Sprintf("Credential %q public key secret %s/%s key %q contains an invalid public key.", username, namespace, ref.Name, ref.Key)
		}
	}
	return true, "", ""
}

func (c *AccessStatusController) secretValue(namespace, username string, ref sshv1.LocalSecretKeyRef) ([]byte, bool, string, string) {
	if ref.Name == "" || ref.Key == "" {
		return nil, false, "InvalidSecretRef", fmt.Sprintf("Credential %q has an incomplete secret reference.", username)
	}
	if c == nil || c.secretIndexer == nil {
		return nil, false, "SecretCacheUnavailable", "Secret informer cache is not available."
	}
	obj, exists, err := c.secretIndexer.GetByKey(accessKey(namespace, ref.Name))
	if err != nil {
		return nil, false, "SecretReadFailed", err.Error()
	}
	if !exists {
		return nil, false, "SecretNotFound", fmt.Sprintf("Credential %q references missing secret %s/%s.", username, namespace, ref.Name)
	}
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, false, "SecretReadFailed", fmt.Sprintf("Secret cache object %s/%s has unexpected type %T.", namespace, ref.Name, obj)
	}
	value, ok := secret.Data[ref.Key]
	if !ok {
		return nil, false, "SecretKeyNotFound", fmt.Sprintf("Credential %q references missing secret key %s/%s:%s.", username, namespace, ref.Name, ref.Key)
	}
	return value, true, "", ""
}

func objectKey(obj any) (string, bool) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return "", false
	}
	return key, true
}
