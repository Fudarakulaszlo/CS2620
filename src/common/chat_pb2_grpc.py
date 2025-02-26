# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import common.chat_pb2 as chat__pb2

GRPC_GENERATED_VERSION = '1.70.0'
GRPC_VERSION = grpc.__version__
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in chat_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class ChatServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.CheckUserExists = channel.unary_unary(
                '/ChatService/CheckUserExists',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.UserExistsResponse.FromString,
                _registered_method=True)
        self.RegisterUser = channel.unary_unary(
                '/ChatService/RegisterUser',
                request_serializer=chat__pb2.RegisterRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.LoginUser = channel.unary_unary(
                '/ChatService/LoginUser',
                request_serializer=chat__pb2.LoginRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.LogoutUser = channel.unary_unary(
                '/ChatService/LogoutUser',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.SendMessage = channel.unary_unary(
                '/ChatService/SendMessage',
                request_serializer=chat__pb2.MessageRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.EditMessage = channel.unary_unary(
                '/ChatService/EditMessage',
                request_serializer=chat__pb2.EditMessageRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.GetMessages = channel.unary_unary(
                '/ChatService/GetMessages',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.MessagesResponse.FromString,
                _registered_method=True)
        self.GetUnreadMessages = channel.unary_unary(
                '/ChatService/GetUnreadMessages',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.MessagesResponse.FromString,
                _registered_method=True)
        self.MarkMessagesRead = channel.unary_unary(
                '/ChatService/MarkMessagesRead',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.DeleteMessage = channel.unary_unary(
                '/ChatService/DeleteMessage',
                request_serializer=chat__pb2.DeleteMessageRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.DeleteUser = channel.unary_unary(
                '/ChatService/DeleteUser',
                request_serializer=chat__pb2.UsernameRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)
        self.ListUsers = channel.unary_unary(
                '/ChatService/ListUsers',
                request_serializer=chat__pb2.EmptyRequest.SerializeToString,
                response_deserializer=chat__pb2.UserListResponse.FromString,
                _registered_method=True)
        self.SaveData = channel.unary_unary(
                '/ChatService/SaveData',
                request_serializer=chat__pb2.EmptyRequest.SerializeToString,
                response_deserializer=chat__pb2.Response.FromString,
                _registered_method=True)


class ChatServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def CheckUserExists(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def RegisterUser(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def LoginUser(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def LogoutUser(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def EditMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetMessages(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetUnreadMessages(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def MarkMessagesRead(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteUser(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ListUsers(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SaveData(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_ChatServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'CheckUserExists': grpc.unary_unary_rpc_method_handler(
                    servicer.CheckUserExists,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.UserExistsResponse.SerializeToString,
            ),
            'RegisterUser': grpc.unary_unary_rpc_method_handler(
                    servicer.RegisterUser,
                    request_deserializer=chat__pb2.RegisterRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'LoginUser': grpc.unary_unary_rpc_method_handler(
                    servicer.LoginUser,
                    request_deserializer=chat__pb2.LoginRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'LogoutUser': grpc.unary_unary_rpc_method_handler(
                    servicer.LogoutUser,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'SendMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.SendMessage,
                    request_deserializer=chat__pb2.MessageRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'EditMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.EditMessage,
                    request_deserializer=chat__pb2.EditMessageRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'GetMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.GetMessages,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.MessagesResponse.SerializeToString,
            ),
            'GetUnreadMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.GetUnreadMessages,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.MessagesResponse.SerializeToString,
            ),
            'MarkMessagesRead': grpc.unary_unary_rpc_method_handler(
                    servicer.MarkMessagesRead,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'DeleteMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteMessage,
                    request_deserializer=chat__pb2.DeleteMessageRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'DeleteUser': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteUser,
                    request_deserializer=chat__pb2.UsernameRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
            'ListUsers': grpc.unary_unary_rpc_method_handler(
                    servicer.ListUsers,
                    request_deserializer=chat__pb2.EmptyRequest.FromString,
                    response_serializer=chat__pb2.UserListResponse.SerializeToString,
            ),
            'SaveData': grpc.unary_unary_rpc_method_handler(
                    servicer.SaveData,
                    request_deserializer=chat__pb2.EmptyRequest.FromString,
                    response_serializer=chat__pb2.Response.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'ChatService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('ChatService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class ChatService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def CheckUserExists(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/CheckUserExists',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.UserExistsResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def RegisterUser(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/RegisterUser',
            chat__pb2.RegisterRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def LoginUser(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/LoginUser',
            chat__pb2.LoginRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def LogoutUser(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/LogoutUser',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def SendMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/SendMessage',
            chat__pb2.MessageRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def EditMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/EditMessage',
            chat__pb2.EditMessageRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/GetMessages',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.MessagesResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetUnreadMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/GetUnreadMessages',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.MessagesResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def MarkMessagesRead(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/MarkMessagesRead',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def DeleteMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/DeleteMessage',
            chat__pb2.DeleteMessageRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def DeleteUser(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/DeleteUser',
            chat__pb2.UsernameRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def ListUsers(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/ListUsers',
            chat__pb2.EmptyRequest.SerializeToString,
            chat__pb2.UserListResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def SaveData(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/ChatService/SaveData',
            chat__pb2.EmptyRequest.SerializeToString,
            chat__pb2.Response.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
