// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: sophos.proto

#include "sophos.pb.h"
#include "sophos.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/method_handler_impl.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace sse {
namespace sophos {

static const char* Sophos_method_names[] = {
  "/sse.sophos.Sophos/setup",
  "/sse.sophos.Sophos/search",
  "/sse.sophos.Sophos/update",
  "/sse.sophos.Sophos/bulk_update",
};

std::unique_ptr< Sophos::Stub> Sophos::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< Sophos::Stub> stub(new Sophos::Stub(channel));
  return stub;
}

Sophos::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_setup_(Sophos_method_names[0], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_search_(Sophos_method_names[1], ::grpc::internal::RpcMethod::SERVER_STREAMING, channel)
  , rpcmethod_update_(Sophos_method_names[2], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_bulk_update_(Sophos_method_names[3], ::grpc::internal::RpcMethod::CLIENT_STREAMING, channel)
  {}

::grpc::Status Sophos::Stub::setup(::grpc::ClientContext* context, const ::sse::sophos::SetupMessage& request, ::google::protobuf::Empty* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_setup_, context, request, response);
}

void Sophos::Stub::experimental_async::setup(::grpc::ClientContext* context, const ::sse::sophos::SetupMessage* request, ::google::protobuf::Empty* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_setup_, context, request, response, std::move(f));
}

::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>* Sophos::Stub::AsyncsetupRaw(::grpc::ClientContext* context, const ::sse::sophos::SetupMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::google::protobuf::Empty>::Create(channel_.get(), cq, rpcmethod_setup_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>* Sophos::Stub::PrepareAsyncsetupRaw(::grpc::ClientContext* context, const ::sse::sophos::SetupMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::google::protobuf::Empty>::Create(channel_.get(), cq, rpcmethod_setup_, context, request, false);
}

::grpc::ClientReader< ::sse::sophos::SearchReply>* Sophos::Stub::searchRaw(::grpc::ClientContext* context, const ::sse::sophos::SearchRequestMessage& request) {
  return ::grpc::internal::ClientReaderFactory< ::sse::sophos::SearchReply>::Create(channel_.get(), rpcmethod_search_, context, request);
}

::grpc::ClientAsyncReader< ::sse::sophos::SearchReply>* Sophos::Stub::AsyncsearchRaw(::grpc::ClientContext* context, const ::sse::sophos::SearchRequestMessage& request, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::sse::sophos::SearchReply>::Create(channel_.get(), cq, rpcmethod_search_, context, request, true, tag);
}

::grpc::ClientAsyncReader< ::sse::sophos::SearchReply>* Sophos::Stub::PrepareAsyncsearchRaw(::grpc::ClientContext* context, const ::sse::sophos::SearchRequestMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::sse::sophos::SearchReply>::Create(channel_.get(), cq, rpcmethod_search_, context, request, false, nullptr);
}

::grpc::Status Sophos::Stub::update(::grpc::ClientContext* context, const ::sse::sophos::UpdateRequestMessage& request, ::google::protobuf::Empty* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_update_, context, request, response);
}

void Sophos::Stub::experimental_async::update(::grpc::ClientContext* context, const ::sse::sophos::UpdateRequestMessage* request, ::google::protobuf::Empty* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_update_, context, request, response, std::move(f));
}

::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>* Sophos::Stub::AsyncupdateRaw(::grpc::ClientContext* context, const ::sse::sophos::UpdateRequestMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::google::protobuf::Empty>::Create(channel_.get(), cq, rpcmethod_update_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>* Sophos::Stub::PrepareAsyncupdateRaw(::grpc::ClientContext* context, const ::sse::sophos::UpdateRequestMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::google::protobuf::Empty>::Create(channel_.get(), cq, rpcmethod_update_, context, request, false);
}

::grpc::ClientWriter< ::sse::sophos::UpdateRequestMessage>* Sophos::Stub::bulk_updateRaw(::grpc::ClientContext* context, ::google::protobuf::Empty* response) {
  return ::grpc::internal::ClientWriterFactory< ::sse::sophos::UpdateRequestMessage>::Create(channel_.get(), rpcmethod_bulk_update_, context, response);
}

::grpc::ClientAsyncWriter< ::sse::sophos::UpdateRequestMessage>* Sophos::Stub::Asyncbulk_updateRaw(::grpc::ClientContext* context, ::google::protobuf::Empty* response, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncWriterFactory< ::sse::sophos::UpdateRequestMessage>::Create(channel_.get(), cq, rpcmethod_bulk_update_, context, response, true, tag);
}

::grpc::ClientAsyncWriter< ::sse::sophos::UpdateRequestMessage>* Sophos::Stub::PrepareAsyncbulk_updateRaw(::grpc::ClientContext* context, ::google::protobuf::Empty* response, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncWriterFactory< ::sse::sophos::UpdateRequestMessage>::Create(channel_.get(), cq, rpcmethod_bulk_update_, context, response, false, nullptr);
}

Sophos::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Sophos_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< Sophos::Service, ::sse::sophos::SetupMessage, ::google::protobuf::Empty>(
          std::mem_fn(&Sophos::Service::setup), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Sophos_method_names[1],
      ::grpc::internal::RpcMethod::SERVER_STREAMING,
      new ::grpc::internal::ServerStreamingHandler< Sophos::Service, ::sse::sophos::SearchRequestMessage, ::sse::sophos::SearchReply>(
          std::mem_fn(&Sophos::Service::search), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Sophos_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< Sophos::Service, ::sse::sophos::UpdateRequestMessage, ::google::protobuf::Empty>(
          std::mem_fn(&Sophos::Service::update), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Sophos_method_names[3],
      ::grpc::internal::RpcMethod::CLIENT_STREAMING,
      new ::grpc::internal::ClientStreamingHandler< Sophos::Service, ::sse::sophos::UpdateRequestMessage, ::google::protobuf::Empty>(
          std::mem_fn(&Sophos::Service::bulk_update), this)));
}

Sophos::Service::~Service() {
}

::grpc::Status Sophos::Service::setup(::grpc::ServerContext* context, const ::sse::sophos::SetupMessage* request, ::google::protobuf::Empty* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Sophos::Service::search(::grpc::ServerContext* context, const ::sse::sophos::SearchRequestMessage* request, ::grpc::ServerWriter< ::sse::sophos::SearchReply>* writer) {
  (void) context;
  (void) request;
  (void) writer;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Sophos::Service::update(::grpc::ServerContext* context, const ::sse::sophos::UpdateRequestMessage* request, ::google::protobuf::Empty* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Sophos::Service::bulk_update(::grpc::ServerContext* context, ::grpc::ServerReader< ::sse::sophos::UpdateRequestMessage>* reader, ::google::protobuf::Empty* response) {
  (void) context;
  (void) reader;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace sse
}  // namespace sophos

