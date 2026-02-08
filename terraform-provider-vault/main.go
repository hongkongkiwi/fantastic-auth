package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"terraform-provider-vault/internal/provider"
)

var (
	version string = "dev"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		Debug:        debugMode,
		ProviderAddr: "vault-auth/vault",
		ProviderFunc: provider.New(version),
	}

	if err := plugin.Serve(opts); err != nil {
		log.Fatal(err.Error())
	}
}
