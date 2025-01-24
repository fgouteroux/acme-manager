// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "François Gouteroux",
            "email": "francois.gouteroux@gmail.com"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/certificate": {
            "put": {
                "description": "Update certificate will revoke the old and create a new certificate with given parameters.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "certificate"
                ],
                "summary": "Update certificate",
                "parameters": [
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd access token here\u003e",
                        "description": "Access token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Certificate body",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.CertificateParams"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/certstore.CertMap"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "429": {
                        "description": "Too Many Requests",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "502": {
                        "description": "Bad Gateway",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            },
            "post": {
                "description": "Create certificate for a given issuer and domain name.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "certificate"
                ],
                "summary": "Create certificate",
                "parameters": [
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd access token here\u003e",
                        "description": "Access token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Certificate body",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.CertificateParams"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/certstore.CertMap"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "429": {
                        "description": "Too Many Requests",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "502": {
                        "description": "Bad Gateway",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            }
        },
        "/certificate/metadata": {
            "get": {
                "description": "Return certificate metadata like SAN,expiration, fingerprint...",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "metadata certificate"
                ],
                "summary": "Read metadata certificate",
                "parameters": [
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd access token here\u003e",
                        "description": "Access token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "letsencrypt",
                        "description": "Certificate issuer",
                        "name": "issuer",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "default": "testfgx.example.com",
                        "description": "Certificate domain",
                        "name": "domain",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/certstore.Certificate"
                            }
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            }
        },
        "/certificate/{issuer}/{domain}": {
            "get": {
                "description": "Return certificate and issuer ca certificate.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "certificate"
                ],
                "summary": "Read certificate",
                "parameters": [
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd access token here\u003e",
                        "description": "Access token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "letsencrypt",
                        "description": "Certificate issuer",
                        "name": "issuer",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "testfgx.example.com",
                        "description": "Certificate domain",
                        "name": "domain",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/certstore.CertMap"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            },
            "delete": {
                "description": "Revoke certificate for the given issuer and domain name.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "certificate"
                ],
                "summary": "Revoke certificate",
                "parameters": [
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd access token here\u003e",
                        "description": "Access token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "letsencrypt",
                        "description": "Certificate issuer",
                        "name": "issuer",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "testfgx.example.com",
                        "description": "Certificate domain",
                        "name": "domain",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "No Content"
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "429": {
                        "description": "Too Many Requests",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "502": {
                        "description": "Bad Gateway",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            }
        },
        "/token": {
            "put": {
                "security": [
                    {
                        "APIKeyAuth": []
                    }
                ],
                "description": "Update token for a given username, scope and expiration time, it will generate a new token.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Update token",
                "parameters": [
                    {
                        "description": "Token Body",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.TokenParams"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "429": {
                        "description": "Too Many Requests",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            },
            "post": {
                "security": [
                    {
                        "APIKeyAuth": []
                    }
                ],
                "description": "Create token for a given username, scope and expiration time.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Create token",
                "parameters": [
                    {
                        "description": "Token Body",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.TokenParams"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/api.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            }
        },
        "/token/{id}": {
            "get": {
                "security": [
                    {
                        "APIKeyAuth": []
                    }
                ],
                "description": "Return token infos like scope, expiration...",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Read token",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Token ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.TokenResponseGet"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            },
            "delete": {
                "security": [
                    {
                        "APIKeyAuth": []
                    }
                ],
                "description": "Revoke token for a given ID.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Revoke token",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Token ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "No Content"
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/api.responseErrorJSON"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "api.CertificateParams": {
            "type": "object",
            "properties": {
                "bundle": {
                    "type": "boolean",
                    "example": false
                },
                "csr": {
                    "type": "string"
                },
                "days": {
                    "type": "integer",
                    "example": 90
                },
                "dns_challenge": {
                    "type": "string",
                    "example": "ns1"
                },
                "domain": {
                    "type": "string",
                    "example": "testfgx.example.com"
                },
                "http_challenge": {
                    "type": "string",
                    "example": ""
                },
                "issuer": {
                    "type": "string",
                    "example": "letsencrypt"
                },
                "renewal_days": {
                    "type": "integer",
                    "example": 30
                },
                "san": {
                    "type": "string",
                    "example": ""
                }
            }
        },
        "api.TokenParams": {
            "type": "object",
            "properties": {
                "duration": {
                    "type": "string",
                    "example": "30d"
                },
                "id": {
                    "type": "string",
                    "example": "021b5075-2d1e-44bd-b5e5-ffc7be7ad4c3"
                },
                "scope": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "read",
                        "create",
                        "update",
                        "delete"
                    ]
                },
                "username": {
                    "type": "string",
                    "example": "testfgx"
                }
            }
        },
        "api.TokenResponse": {
            "type": "object",
            "properties": {
                "duration": {
                    "type": "string"
                },
                "expires": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "scope": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "token": {
                    "type": "string"
                },
                "tokenHash": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "api.TokenResponseGet": {
            "type": "object",
            "properties": {
                "duration": {
                    "type": "string"
                },
                "expires": {
                    "type": "string"
                },
                "scope": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "tokenHash": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "api.responseErrorJSON": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "example": "error"
                }
            }
        },
        "certstore.CertMap": {
            "type": "object",
            "properties": {
                "bundle": {
                    "type": "boolean",
                    "example": false
                },
                "ca_issuer": {
                    "type": "string",
                    "example": "-----BEGIN CERTIFICATE-----\n..."
                },
                "cert": {
                    "type": "string",
                    "example": "-----BEGIN CERTIFICATE-----\n..."
                },
                "csr": {
                    "type": "string"
                },
                "days": {
                    "type": "integer",
                    "example": 90
                },
                "dns_challenge": {
                    "type": "string",
                    "example": "ns1"
                },
                "domain": {
                    "type": "string",
                    "example": "testfgx.example.com"
                },
                "expires": {
                    "type": "string",
                    "example": "2025-04-09 09:56:34 +0000 UTC"
                },
                "fingerprint": {
                    "type": "string",
                    "example": "3c7bccea1992d5095e7ab8c38f247352cd75ff26cdb95972d34ad54ebcef36af"
                },
                "http_challenge": {
                    "type": "string",
                    "example": ""
                },
                "issuer": {
                    "type": "string",
                    "example": "letsencrypt"
                },
                "owner": {
                    "type": "string",
                    "example": "testfgx"
                },
                "renewal_days": {
                    "type": "integer",
                    "example": 30
                },
                "san": {
                    "type": "string",
                    "example": ""
                },
                "url": {
                    "type": "string",
                    "example": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/4b63b4e8b6109"
                }
            }
        },
        "certstore.Certificate": {
            "type": "object",
            "properties": {
                "bundle": {
                    "type": "boolean",
                    "example": false
                },
                "csr": {
                    "type": "string"
                },
                "days": {
                    "type": "integer",
                    "example": 90
                },
                "dns_challenge": {
                    "type": "string",
                    "example": "ns1"
                },
                "domain": {
                    "type": "string",
                    "example": "testfgx.example.com"
                },
                "expires": {
                    "type": "string",
                    "example": "2025-04-09 09:56:34 +0000 UTC"
                },
                "fingerprint": {
                    "type": "string",
                    "example": "3c7bccea1992d5095e7ab8c38f247352cd75ff26cdb95972d34ad54ebcef36af"
                },
                "http_challenge": {
                    "type": "string",
                    "example": ""
                },
                "issuer": {
                    "type": "string",
                    "example": "letsencrypt"
                },
                "owner": {
                    "type": "string",
                    "example": "testfgx"
                },
                "renewal_days": {
                    "type": "integer",
                    "example": 30
                },
                "san": {
                    "type": "string",
                    "example": ""
                }
            }
        }
    },
    "securityDefinitions": {
        "APIKeyAuth": {
            "type": "apiKey",
            "name": "X-API-Key",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "acme manager",
	Description:      "Manages acme certificate and deploy them on servers",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
