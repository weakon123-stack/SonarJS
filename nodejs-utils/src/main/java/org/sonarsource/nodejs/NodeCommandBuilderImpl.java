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
package org.sonarsource.nodejs;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import org.sonar.api.config.Configuration;
import org.sonar.api.internal.google.common.annotations.VisibleForTesting;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

class NodeCommandBuilderImpl implements NodeCommandBuilder {

  private static final Logger LOG = Loggers.get(NodeCommandBuilderImpl.class);

  public static final String NODE_EXECUTABLE_DEFAULT = "node";
  private static final String NODE_EXECUTABLE_DEFAULT_MACOS = "package/node_modules/run-node/run-node";

  private static final String NODE_EXECUTABLE_PROPERTY = "sonar.nodejs.executable";
  private static final String NODE_EXECUTABLE_PROPERTY_TS = "sonar.typescript.node";

  private static final Pattern NODEJS_VERSION_PATTERN = Pattern.compile("v?(\\d+)\\.\\d+\\.\\d+");

  private final NodeCommand.ProcessWrapper processWrapper;
  private Integer minNodeVersion;
  private Configuration configuration;
  private List<String> args = new ArrayList<>();
  private List<String> nodeJsArgs = new ArrayList<>();
  private Consumer<String> outputConsumer = LOG::info;
  private Consumer<String> errorConsumer = LOG::error;
  private String scriptFilename;
  private List<Path> nodePath = new ArrayList<>();
  private BundlePathResolver pathResolver;

  NodeCommandBuilderImpl(NodeCommand.ProcessWrapper processWrapper) {
    this.processWrapper = processWrapper;
  }

  @Override
  public NodeCommandBuilder minNodeVersion(int minNodeVersion) {
    this.minNodeVersion = minNodeVersion;
    return this;
  }

  @Override
  public NodeCommandBuilder configuration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  @Override
  public NodeCommandBuilder addToNodePath(Path path) {
    if (path == null) {
      throw new IllegalArgumentException("Node path can't be null");
    }
    nodePath.add(path);
    return this;
  }

  @Override
  public NodeCommandBuilder maxOldSpaceSize(int maxOldSpaceSize) {
    nodeJsArgs("--max-old-space-size=" + maxOldSpaceSize);
    return this;
  }

  @Override
  public NodeCommandBuilder nodeJsArgs(String... nodeJsArgs) {
    this.nodeJsArgs.addAll(Arrays.asList(nodeJsArgs));
    return this;
  }

  @Override
  public NodeCommandBuilder script(String scriptFilename) {
    this.scriptFilename = scriptFilename;
    return this;
  }

  @Override
  public NodeCommandBuilder scriptArgs(String... args) {
    this.args.addAll(Arrays.asList(args));
    return this;
  }

  @Override
  public NodeCommandBuilder outputConsumer(Consumer<String> consumer) {
    this.outputConsumer = consumer;
    return this;
  }

  @Override
  public NodeCommandBuilder errorConsumer(Consumer<String> consumer) {
    this.errorConsumer = consumer;
    return this;
  }

  @Override
  public NodeCommandBuilder pathResolver(BundlePathResolver pathResolver) {
    this.pathResolver = pathResolver;
    return this;
  }

  /**
   * Retrieves node executable from sonar.node.executable property or using default if absent.
   * Then will check Node.js version by running {@code node -v}, then
   * returns {@link NodeCommand} instance.
   *
   * @throws NodeCommandException when actual Node.js version doesn't satisfy minimum version requested,
   * or if failed to run {@code node -v}
   */
  @Override
  public NodeCommand build() throws NodeCommandException, IOException {
    String nodeExecutable = retrieveNodeExecutableFromConfig(configuration);
    checkNodeCompatibility(nodeExecutable);

    if (nodeJsArgs.isEmpty() && scriptFilename == null && args.isEmpty()) {
      throw new IllegalArgumentException("Missing arguments for Node.js.");
    }
    if (scriptFilename == null && !args.isEmpty()) {
      throw new IllegalArgumentException("No script provided, but script arguments found.");
    }
    return new NodeCommand(
      processWrapper,
      nodeExecutable,
      nodePath,
      nodeJsArgs,
      scriptFilename,
      args,
      outputConsumer,
      errorConsumer);
  }

  private void checkNodeCompatibility(String nodeExecutable) throws NodeCommandException {
    if (minNodeVersion == null) {
      return;
    }
    LOG.debug("Checking Node.js version");

    String actualVersion = getVersion(nodeExecutable);
    boolean isCompatible = checkVersion(actualVersion, minNodeVersion);
    if (!isCompatible) {
      throw new NodeCommandException(String.format("Only Node.js v%s or later is supported, got %s.", minNodeVersion, actualVersion));
    }

    LOG.debug("Using Node.js {}.", actualVersion);
  }

  @VisibleForTesting
  static boolean checkVersion(String actualVersion, int requiredVersion) throws NodeCommandException {
    Matcher versionMatcher = NODEJS_VERSION_PATTERN.matcher(actualVersion);
    if (versionMatcher.lookingAt()) {
      int major = Integer.parseInt(versionMatcher.group(1));
      if (major < requiredVersion) {
        return false;
      }
    } else {
      throw new NodeCommandException("Failed to parse Node.js version, got '" + actualVersion + "'");
    }

    return true;
  }

  private String getVersion(String nodeExecutable) throws NodeCommandException {
    StringBuilder output = new StringBuilder();
    NodeCommand nodeCommand = new NodeCommand(processWrapper, nodeExecutable, emptyList(), singletonList("-v"), null, emptyList(), output::append, LOG::error);
    nodeCommand.start();
    int exitValue = nodeCommand.waitFor();
    if (exitValue != 0) {
      throw new NodeCommandException("Failed to determine the version of Node.js, exit value " + exitValue + ". Executed: '" + nodeCommand.toString() + "'");
    }
    return output.toString();
  }

  private String retrieveNodeExecutableFromConfig(@Nullable Configuration configuration) throws NodeCommandException, IOException {
    if (configuration != null && (configuration.hasKey(NODE_EXECUTABLE_PROPERTY) || configuration.hasKey(NODE_EXECUTABLE_PROPERTY_TS))) {
      String nodeExecutable = "";
      String usedProperty = "";

      if (configuration.hasKey(NODE_EXECUTABLE_PROPERTY_TS)) {
        LOG.warn("The use of " + NODE_EXECUTABLE_PROPERTY_TS + " is deprecated, use "
          + NODE_EXECUTABLE_PROPERTY + " instead.");
        usedProperty = NODE_EXECUTABLE_PROPERTY_TS;
        nodeExecutable = configuration.get(NODE_EXECUTABLE_PROPERTY_TS).get();
      }

      if (configuration.hasKey(NODE_EXECUTABLE_PROPERTY)) {
        usedProperty = NODE_EXECUTABLE_PROPERTY;
        nodeExecutable = configuration.get(NODE_EXECUTABLE_PROPERTY).get();
      }

      File file = new File(nodeExecutable);
      if (file.exists()) {
        LOG.info("Using Node.js executable {} from property {}.", file.getAbsoluteFile(), usedProperty);
        return nodeExecutable;
      } else {
        LOG.error("Provided Node.js executable file does not exist. Property '{}' was to '{}'", usedProperty, nodeExecutable);
        throw new NodeCommandException("Provided Node.js executable file does not exist.");
      }
    }

    String defaultNode = NODE_EXECUTABLE_DEFAULT;
    // on Mac when e.g. IntelliJ is launched from dock, node will often not be available via PATH, because PATH is configured
    // in .bashrc or similar, thus we launch node via 'run-node', which should load required configuration
    if (processWrapper.isMac()) {
      defaultNode = pathResolver.resolve(NODE_EXECUTABLE_DEFAULT_MACOS);
      File file = new File(defaultNode);
      if (!file.exists()) {
        LOG.error("Default Node.js executable for MacOS does not exist. Value '{}'. Consider setting Node.js location through property '{}'", defaultNode, NODE_EXECUTABLE_PROPERTY);
        throw new NodeCommandException("Default Node.js executable for MacOS does not exist.");
      } else {
        Files.setPosixFilePermissions(file.toPath(), EnumSet.of(PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.OWNER_READ));
      }
    }
    LOG.debug("Using default Node.js executable: '{}'.", defaultNode);
    return defaultNode;
  }
}
