# neon-traefik

### Maintenance Instructions

1. Rebase onto next branch version, ensure branch is referencing the same commit as version's tag

    ```bash
    # Get all upstream
    git fetch -v --all
    # From the current neon branch, create next version neon branch
    git checkout -b v3.7-neon
    # If not already on the tagged release commit for the next version, reset until there
    git reset --hard HEAD~1
    # Inspect with log, repeat reset until on appropriate commit
    git log
    # Once on the tagged release commit, rebase from upstream
    git rebase upstream/v3.7
    ```

2. Resolve any rebase merge errors  
    - go.mod and go.sum  
        - github.com/go-jose/go-jose is a direct instead of indirect dependency
        - github.com/tink-crypto/tink-go is a new direct dependency
    - Run go mod tidy to resolve any package state
        - `go mod tidy`

3. Regnerate generated code
    ```bash
    make generate-crd
    ```

    - Post generate modifications
        - Check scripts/code-gen.sh
        - Clean up any failed commands (from `sed` for example)
            ```bash
            # Remove leading '---' from the concatenated file (files with multiple resources should not start with ---)
            sed -i '1{/^---$/d;}' "${CURRENT_DIR}"/docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml
            ```
        - Remove leading `---` from /docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml

4. Build and test
    ```bash
    cd .neon
    ./build.sh
    ./test.sh
    ```

    - Remove leading `---` from /docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml

5. Resolve any necessary code modifications or issues
    - Inspect diff from main traefik code repo (between current neon version and next traefik version)
    - Sanity check any fundamental changes
    - Walk through current neon-traefik commit and inspect any related file changes from upstream

6. Update .neon/Dockerfile from current release version of Dockerfile
    - https://github.com/traefik/traefik-library-image/blob/v3.7.10/v3.7/alpine/Dockerfile

7. Compare and update workflows from latest traefik version and neon versions

8. Test traefik build

### Releasing

1. Create and push tag for new version
    ```bash
    # Example: git tag v3.7.10-neon-v1
    git tag ${TRAEFIK_VERSION}-neon-${NEON_VERSION}
    # Example: git push origin v3.7.10-neon-v1
    git push origin ${TRAEFIK_VERSION}-neon-${NEON_VERSION}
    ```
