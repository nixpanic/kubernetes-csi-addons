/*
Copyright 2024 The Kubernetes-CSI-Addons Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package token

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type tokenResolver struct {
	kubeclient     *kubernetes.Clientset
	namespace      string
	serviceAccount string

	token      string
	expiration metav1.Time
}

func WithServiceAccountToken(kubeclient *kubernetes.Clientset, namespace, serviceAccount string) grpc.DialOption {
	tr := tokenResolver{
		kubeclient:     kubeclient,
		namespace:      namespace,
		serviceAccount: serviceAccount,
		expiration:     metav1.Now(),
	}

	return grpc.WithUnaryInterceptor(tr.addAuthorizationHeader)
}

func (tr *tokenResolver) addAuthorizationHeader(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	logger := log.FromContext(ctx)
	logger.WithValues("Namespace", tr.namespace, "ServiceAccount", tr.serviceAccount)

	token, err := tr.getToken(ctx)
	if err != nil {
		logger.Error(err, "failed to get token for ServiceAccount")

		return err
	}

	authCtx := metadata.AppendToOutgoingContext(ctx, "Authorization", "Bearer "+token)
	return invoker(authCtx, method, req, reply, cc, opts...)
}

func (tr *tokenResolver) getToken(ctx context.Context) (string, error) {
	now := metav1.Now()
	if tr.expiration.Before(&now) {
		// token expired
		return tr.refreshToken(ctx)
	}

	return tr.token, nil
}

func (tr *tokenResolver) refreshToken(ctx context.Context) (string, error) {
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{"csi-addons"},
		},
	}

	tres, err := tr.kubeclient.CoreV1().ServiceAccounts(tr.namespace).CreateToken(ctx, tr.serviceAccount, treq, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	tr.token = tres.Status.Token
	tr.expiration = tres.Status.ExpirationTimestamp

	return tr.token, nil
}
