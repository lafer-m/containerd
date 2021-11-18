## dep patrick service pb

```
cd api/services/auth
protoc -I. --proto_path=./proto --go_out=plugins=grpc:./proto ./proto/identities.proto
protoc -I. --proto_path=./proto --go_out=plugins=grpc:./proto ./proto/aksk.proto
```

