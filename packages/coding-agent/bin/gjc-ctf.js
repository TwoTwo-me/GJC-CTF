#!/usr/bin/env bun
import { runCtfCli } from "../src/ctf/cli.ts";

await runCtfCli(process.argv.slice(2));
