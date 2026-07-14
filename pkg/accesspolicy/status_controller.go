package accesspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
	"xiaoshiai.cn/kube-ssh/pkg/kube"
)

type AccessStatusUpdater func(context.Context, *sshv1.Access) (*sshv1.Access, error)

type AccessStatusController struct {
	accesses      Store
	pods          PodLister
	secretIndexer cache.Indexer
	updateStatus  AccessStatusUpdater
	policy        ContainerPolicy
	endpoints     []sshv1.AccessStatusEndpoint
	queue         workqueue.TypedRateLimitingInterface[string]
}

type AccessStatusControllerOptions struct {
	Policy    ContainerPolicy
	Endpoints []sshv1.AccessStatusEndpoint
}

func NewAccessStatusController(accesses Store, pods PodLister, secretIndexer cache.Indexer, updateStatus AccessStatusUpdater, options AccessStatusControllerOptions) *AccessStatusController {
	return &AccessStatusController{
		accesses:      accesses,
		pods:          pods,
		secretIndexer: secretIndexer,
		updateStatus:  updateStatus,
		policy:        options.Policy,
		endpoints:     append([]sshv1.AccessStatusEndpoint(nil), options.Endpoints...),
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
		equality.Semantic.DeepEqual(access.Status.Endpoints, status.Endpoints) &&
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
		Endpoints:          accessStatusEndpoints(access, c.endpoints),
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
	selectablePods := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if c.statusContainer(pod, access) != "" {
			selectablePods = append(selectablePods, pod)
		}
	}
	if len(candidatePods(selectablePods)) == 0 {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               sshv1.AccessConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: access.Generation,
			Reason:             "NoBackends",
			Message:            "Access selector matches no active Pods.",
		})
		return status
	}
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               sshv1.AccessConditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: access.Generation,
		Reason:             "BackendAvailable",
		Message:            "Access has at least one active Pod backend.",
	})
	return status
}

func accessStatusEndpoints(access *sshv1.Access, advertised []sshv1.AccessStatusEndpoint) []sshv1.AccessStatusEndpoint {
	if access == nil || len(advertised) == 0 {
		return nil
	}
	username := access.Namespace + "." + access.Name
	endpoints := make([]sshv1.AccessStatusEndpoint, 0, len(advertised))
	for _, endpoint := range advertised {
		endpoint.Username = username
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func (c *AccessStatusController) statusContainer(pod corev1.Pod, access *sshv1.Access) string {
	_, defaultContainer, err := kube.ResolvePodContainer(&pod, "")
	if err != nil {
		return ""
	}
	for _, container := range pod.Spec.Containers {
		explicit := container.Name != defaultContainer
		accessAllowed := kube.ContainerModeAllows(c.policy.DefaultMode, explicit, container.Name, defaultContainer)
		if len(access.Spec.Containers) > 0 {
			accessAllowed = containerAllowed(access.Spec.Containers, container.Name)
		}
		if !accessAllowed || !kube.ContainerModeAllows(c.policy.LimitMode, explicit, container.Name, defaultContainer) {
			continue
		}
		for _, credential := range access.Spec.Credentials {
			if containerAllowed(credential.Containers, container.Name) {
				return container.Name
			}
		}
	}
	return ""
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
		if ok, message := validateCapabilityPolicy(credential.Capabilities); !ok {
			return metav1.ConditionFalse, "InvalidCapabilityPolicy", fmt.Sprintf("Credential %q: %s", credential.Username, message)
		}
		if len(access.Spec.Containers) > 0 {
			for _, container := range credential.Containers {
				if container == "*" {
					continue
				}
				if !containerAllowed(access.Spec.Containers, container) {
					return metav1.ConditionFalse, "InvalidContainerPolicy", fmt.Sprintf("Credential %q container %q is not exposed by the Access.", credential.Username, container)
				}
			}
		}
	}
	return metav1.ConditionTrue, "Valid", "Access spec and referenced credentials are valid."
}

func validateCapabilityPolicy(policy sshv1.CapabilityPolicy) (bool, string) {
	if policy.LocalForward != nil {
		for _, expression := range policy.LocalForward.AllowDestinations {
			if !validForwardExpression(expression) {
				return false, fmt.Sprintf("invalid local forward destination %q", expression)
			}
		}
	}
	if policy.RemoteForward != nil {
		for _, expression := range policy.RemoteForward.AllowBinds {
			if !validForwardExpression(expression) {
				return false, fmt.Sprintf("invalid remote forward bind %q", expression)
			}
		}
	}
	return true, ""
}

func validForwardExpression(expression string) bool {
	if expression == "*" || expression == "*:*" {
		return true
	}
	host, port, err := net.SplitHostPort(expression)
	return err == nil && host != "" && port != ""
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
