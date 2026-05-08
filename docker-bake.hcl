variable "REGISTRY" {
  default = "ghcr.io"
}

variable "IMAGE_NAME" {
  default = "gnurub/bastionflow"
}

variable "VERSION" {
  default = "0.1.0"
}

variable "REVISION" {
  default = "dev"
}

variable "SOURCE" {
  default = "https://github.com/GNURub/bastionflow"
}

variable "CREATED" {
  default = "unknown"
}

variable "PLATFORMS" {
  default = "linux/amd64,linux/arm64"
}

group "default" {
  targets = ["bastionflow"]
}

target "bastionflow" {
  context = "."
  dockerfile = "Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = [
    "${REGISTRY}/${IMAGE_NAME}:${VERSION}",
    "${REGISTRY}/${IMAGE_NAME}:latest"
  ]
  args = {
    VERSION = VERSION
    REVISION = REVISION
    SOURCE = SOURCE
    CREATED = CREATED
  }
  labels = {
    "org.opencontainers.image.title" = "BastionFlow"
    "org.opencontainers.image.source" = SOURCE
    "org.opencontainers.image.version" = VERSION
    "org.opencontainers.image.revision" = REVISION
    "org.opencontainers.image.licenses" = "MIT"
  }
}
