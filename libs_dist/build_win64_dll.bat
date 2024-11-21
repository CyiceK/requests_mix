:: build win64 dll
CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -v -buildmode=c-shared -o requests-go-win64.dll export.go