/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import * as espree from "espree";
import * as babel from "babel-eslint";
import { Linter, SourceCode } from "eslint";
import { ParsingError } from "./analyzer";
import * as VueJS from "vue-eslint-parser";

// this value is taken from typescript-estree
// still we might consider extending this range
// if everything which we need is working on older/newer versions
const TYPESCRIPT_MINIMUM_VERSION = "3.2.1";
const TYPESCRIPT_MAXIMUM_VERSION = "3.8.0";

export const PARSER_CONFIG_MODULE: Linter.ParserOptions = {
  tokens: true,
  comment: true,
  loc: true,
  range: true,
  ecmaVersion: 2018,
  sourceType: "module",
  codeFrame: false,
  ecmaFeatures: {
    jsx: true,
    globalReturn: true,
  },
};

// 'script' source type forces not strict
export const PARSER_CONFIG_SCRIPT: Linter.ParserOptions = {
  ...PARSER_CONFIG_MODULE,
  sourceType: "script",
};

export type Parse = (
  fileContent: string,
  filePath: string,
  tsConfigs?: string[],
) => SourceCode | ParsingError;

export function parseJavaScriptSourceFile(fileContent: string): SourceCode | ParsingError {
  let parseFunctions = [espree.parse, babel.parseForESLint];
  if (fileContent.includes("@flow")) {
    parseFunctions = [babel.parseForESLint];
  }

  let exceptionToReport: ParseException | null = null;
  for (const parseFunction of parseFunctions) {
    for (const config of [PARSER_CONFIG_MODULE, PARSER_CONFIG_SCRIPT]) {
      const result = parse(parseFunction, config, fileContent);
      if (result instanceof SourceCode) {
        return result;
      } else if (!exceptionToReport) {
        exceptionToReport = result;
      }
    }
  }

  // if we reach this point, we are sure that "exceptionToReport" is defined
  return {
    line: exceptionToReport!.lineNumber,
    message: exceptionToReport!.message,
    code: ParseExceptionCode.Parsing,
  };
}

export function parseTypeScriptSourceFile(
  fileContent: string,
  filePath: string,
  tsConfigs?: string[],
): SourceCode | ParsingError {
  try {
    checkTypeScriptVersionCompatibility(require("typescript").version);
    // we load the typescript parser dynamically, so we don't need typescript dependency when analyzing pure JS project
    const tsParser = require("@typescript-eslint/parser");
    const result = tsParser.parseForESLint(fileContent, {
      ...PARSER_CONFIG_MODULE,
      filePath: filePath,
      project: tsConfigs,
      loggerFn: console.log,
    });
    return new SourceCode({ ...result, parserServices: result.services, text: fileContent });
  } catch (exception) {
    return {
      line: exception.lineNumber,
      message: exception.message,
      code: parseExceptionCodeOf(exception.message),
    };
  }
}

// exported for testing
export function checkTypeScriptVersionCompatibility(currentVersion: string) {
  if (currentVersion >= TYPESCRIPT_MAXIMUM_VERSION) {
    console.log(
      `WARN You are using version of TypeScript ${currentVersion} which is not officially supported; supported versions >=${TYPESCRIPT_MINIMUM_VERSION} <${TYPESCRIPT_MAXIMUM_VERSION}`,
    );
  } else if (currentVersion < TYPESCRIPT_MINIMUM_VERSION) {
    throw {
      message: `You are using version of TypeScript ${currentVersion} which is not supported; supported versions >=${TYPESCRIPT_MINIMUM_VERSION}`,
    };
  }
}

export function unloadTypeScriptEslint() {
  const tsParser = require.resolve("@typescript-eslint/parser");
  delete require.cache[tsParser];
}

export function parseVueSourceFile(fileContent: string): SourceCode | ParsingError {
  let exceptionToReport: ParseException | null = null;
  for (const config of [PARSER_CONFIG_MODULE, PARSER_CONFIG_SCRIPT]) {
    try {
      const result = VueJS.parseForESLint(fileContent, config);
      return new SourceCode(fileContent, result.ast as any);
    } catch (exception) {
      exceptionToReport = exception;
    }
  }
  // if we reach this point, we are sure that "exceptionToReport" is defined
  return {
    line: exceptionToReport!.lineNumber,
    message: exceptionToReport!.message,
    code: ParseExceptionCode.Parsing,
  };
}

export function parse(
  parse: Function,
  config: Linter.ParserOptions,
  fileContent: string,
): SourceCode | ParseException {
  try {
    const result = parse(fileContent, config);
    if (result.ast) {
      return new SourceCode({ text: fileContent, ...result });
    } else {
      return new SourceCode(fileContent, result);
    }
  } catch (exception) {
    return exception;
  }
}

export type ParseException = {
  lineNumber?: number;
  message: string;
  code: string;
};

export enum ParseExceptionCode {
  Parsing = "PARSING",
  MissingTypeScript = "MISSING_TYPESCRIPT",
  UnsupportedTypeScript = "UNSUPPORTED_TYPESCRIPT",
  GeneralError = "GENERAL_ERROR",
}

// exported for testing
export function parseExceptionCodeOf(exceptionMsg: string): ParseExceptionCode {
  if (exceptionMsg.startsWith("Cannot find module 'typescript'")) {
    return ParseExceptionCode.MissingTypeScript;
  } else if (exceptionMsg.startsWith("You are using version of TypeScript")) {
    return ParseExceptionCode.UnsupportedTypeScript;
  } else {
    return ParseExceptionCode.Parsing;
  }
}
