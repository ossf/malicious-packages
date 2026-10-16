#!/usr/bin/env node
// Copyright 2026 Malicious Packages Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"use strict";

const fs = require("node:fs");
const Ajv2020 = require("ajv/dist/2020").default;
const draft6MetaSchema = require("ajv/dist/refs/json-schema-draft-06.json");
const addFormats = require("ajv-formats");
const { default: betterAjvErrors } = require("better-ajv-errors");

const OUTPUT_FORMAT_JS = "js";
const PARSE_ERROR_TITLE = "JSON Parse Error";
const SCHEMA_ERROR_TITLE = "JSON Schema Validation Error";

function parseArgs(argv) {
  const args = argv.slice(2);
  if (args.length < 2) {
    console.error("Usage: node validate.js <schema.json> <data.json>...");
    process.exit(2);
  }
  return Object.freeze({
    schemaPath: args[0],
    dataPaths: Object.freeze(args.slice(1)),
  });
}

function createValidator() {
  // allErrors is required so better-ajv-errors has the complete error tree
  // to prune redundant branch errors (e.g. oneOf/anyOf noise).
  const ajv = new Ajv2020({
    allErrors: true,
    strictTypes: false,
  });
  ajv.addMetaSchema(draft6MetaSchema);
  addFormats(ajv, { mode: "fast" });

  return ajv;
}

// GitHub Actions workflow commands truncate anything after a literal newline,
// so percent-encode %, \r, and \n in the message payload.
function escapeWorkflowMessage(message) {
  return message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

function validateFile(dataPath, schema, validate) {
  // Keep the raw JSON string so better-ajv-errors can parse the original AST
  // and report exact line, column, and byte offset locations from dataPath.
  const rawData = fs.readFileSync(dataPath, "utf8");

  let data;
  try {
    data = JSON.parse(rawData);
  } catch (err) {
    // Output a helpful GitHub error if the message cannot be parsed.
    const posMatch = err.message.match(/(?:at )?position (\d+)/);
    const msg = escapeWorkflowMessage(err.message);
    if (err instanceof SyntaxError && posMatch) {
      const pos = parseInt(posMatch[1], 10);
      // Split all text prior to the error location by line breaks.
      const textUpToError = rawData.substring(0, pos);
      const lines = textUpToError.split("\n");
      const col = lines[lines.length - 1].length + 1;
      console.error(
        `::error file=${dataPath},line=${lines.length},col=${col},title=${PARSE_ERROR_TITLE}::${msg}`
      );
    } else {
      console.error(
        `::error file=${dataPath},title=${PARSE_ERROR_TITLE}::${msg}`
      );
    }
    return false;
  }

  // Validate the report.
  const valid = validate(data);
  if (valid) {
    return true;
  }

  // Reformat the errors.
  const errors = betterAjvErrors(schema, data, validate.errors ?? [], {
    format: OUTPUT_FORMAT_JS,
    json: rawData,
  });

  // Ensure that at least one error is output if validation failed.
  if (errors.length === 0) {
    console.error(
      `::error file=${dataPath},title=${SCHEMA_ERROR_TITLE}::invalid json`
    );
    return false;
  }

  // Transform the errors into GitHub error messages.
  errors.forEach((error) => {
    const baseMessage = error.error.trim();
    const message = error.suggestion
      ? `${baseMessage}. ${error.suggestion.trim()}`
      : baseMessage;
    const start = error.start
      ? `,line=${error.start.line},col=${error.start.column}`
      : "";
    const end = error.end
      ? `,endLine=${error.end.line},endColumn=${error.end.column}`
      : "";
    console.error(
      `::error file=${dataPath}${start}${end},title=${SCHEMA_ERROR_TITLE}::${escapeWorkflowMessage(message)}`
    );
  });

  return false;
}

function main() {
  const { schemaPath, dataPaths } = parseArgs(process.argv);

  const rawSchema = fs.readFileSync(schemaPath, "utf8");
  const schema = JSON.parse(rawSchema);
  const ajv = createValidator();
  const validate = ajv.compile(schema);

  const results = dataPaths.map((dataPath) =>
    validateFile(dataPath, schema, validate)
  );

  if (!results.every(Boolean)) {
    process.exit(1);
  }
}

main();
