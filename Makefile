.PHONY: test test-verbose test-cover test-gorm test-ent

test:
	go test ./... -race -count=1

test-verbose:
	go test ./... -v -race -count=1

test-cover:
	go test ./... -race -count=1 -coverprofile=coverage.out
	go tool cover -html=coverage.out

test-gorm:
	go test ./tests/... -run 'TestPassport|TestClientManagement|TestBackends/gorm' -race -count=1

test-ent:
	go test ./tests/... -run 'TestEnt|TestBackends/ent' -race -count=1