package auth

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"
)

type GetUsersResponseWrapper struct {
	Users         []*UserWrapper `protobuf:"bytes,1,rep,name=users,proto3" json:"users,omitempty"`
	NextPageToken string         `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

type UserWrapper struct {
	Id               string           `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	ResourceVersion  string           `protobuf:"bytes,2,opt,name=resource_version,json=resourceVersion,proto3" json:"resource_version,omitempty"`
	Spec             *UserSpecWrapper `protobuf:"bytes,3,opt,name=spec,proto3" json:"spec,omitempty"`
	State            UserState        `protobuf:"varint,4,opt,name=state,proto3,enum=api.auth.v1.UserState" json:"state,omitempty"`
	RequestId        string           `protobuf:"bytes,5,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Invitation       *Invitation      `protobuf:"bytes,6,opt,name=invitation,proto3" json:"invitation,omitempty"`
	CreatedTime      *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=created_time,json=createdTime,proto3" json:"created_time,omitempty"`
	LastModifiedTime *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=last_modified_time,json=lastModifiedTime,proto3" json:"last_modified_time,omitempty"`
}

type UserSpecWrapper struct {
	Email                string                `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	AccountRole          AccountRole           `protobuf:"bytes,3,opt,name=account_role,json=accountRole,proto3" json:"account_role,omitempty"`
	NamespacePermissions []NamespacePermission `protobuf:"bytes,4,opt,name=namespace_permissions,json=namespacePermissions,proto3" json:"namespace_permissions,omitempty"`
}

type AccountRole struct {
	Id   string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Role string `protobuf:"bytes,2,opt,name=role,proto3" json:"role,omitempty"`
}

type NamespacePermission struct {
	Id         string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Namespace  string `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Permission string `protobuf:"bytes,3,opt,name=permission,proto3" json:"permission,omitempty"`
}

func (*GetUsersResponseWrapper) Reset()        {}
func (*GetUsersResponseWrapper) ProtoMessage() {}
func (this *GetUsersResponseWrapper) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GetUsersResponse{`,
		`Users:` + fmt.Sprintf("%v", this.Users) + `,`,
		`NextPageToken:` + fmt.Sprintf("%v", this.NextPageToken) + `,`,
		`}`,
	}, "")
	return s
}

func (*UserWrapper) Reset()        {}
func (*UserWrapper) ProtoMessage() {}
func (this *UserWrapper) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&User{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`ResourceVersion:` + fmt.Sprintf("%v", this.ResourceVersion) + `,`,
		`Spec:` + strings.Replace(this.Spec.String(), "UserSpec", "UserSpec", 1) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
		`RequestId:` + fmt.Sprintf("%v", this.RequestId) + `,`,
		`Invitation:` + strings.Replace(this.Invitation.String(), "Invitation", "Invitation", 1) + `,`,
		`CreatedTime:` + strings.Replace(fmt.Sprintf("%v", this.CreatedTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`LastModifiedTime:` + strings.Replace(fmt.Sprintf("%v", this.LastModifiedTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`}`,
	}, "")
	return s
}

func (*UserSpecWrapper) Reset()        {}
func (*UserSpecWrapper) ProtoMessage() {}
func (this *UserSpecWrapper) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&UserSpec{`,
		`Email:` + fmt.Sprintf("%v", this.Email) + `,`,
		`AccountRole:` + fmt.Sprintf("%v", this.AccountRole) + `,`,
		`NamespacePermissions:` + fmt.Sprintf("%v", this.NamespacePermissions) + `,`,
		`}`,
	}, "")
	return s
}

func (*AccountRole) Reset()        {}
func (*AccountRole) ProtoMessage() {}
func (this *AccountRole) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AccountRole{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`Role:` + fmt.Sprintf("%v", this.Role) + `,`,
		`}`,
	}, "")
	return s
}

func (*NamespacePermission) Reset()        {}
func (*NamespacePermission) ProtoMessage() {}
func (this *NamespacePermission) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&NamespacePermission{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`Namespace:` + fmt.Sprintf("%v", this.Namespace) + `,`,
		`Permission:` + fmt.Sprintf("%v", this.Permission) + `,`,
		`}`,
	}, "")
	return s
}
