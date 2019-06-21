/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2019 SonarSource SA
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
package org.sonar.plugins.javascript;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.sonar.sslr.api.RecognitionException;
import com.sonar.sslr.api.typed.ActionParser;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import org.apache.commons.lang.ArrayUtils;
import org.sonar.api.SonarProduct;
import org.sonar.api.batch.fs.FilePredicate;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.InputFile.Type;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.rule.CheckFactory;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.cpd.NewCpdTokens;
import org.sonar.api.batch.sensor.highlighting.NewHighlighting;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.batch.sensor.symbol.NewSymbolTable;
import org.sonar.api.issue.NoSonarFilter;
import org.sonar.api.measures.FileLinesContextFactory;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.javascript.checks.CheckList;
import org.sonar.javascript.checks.ParsingErrorCheck;
import org.sonar.javascript.cpd.CpdVisitor;
import org.sonar.javascript.highlighter.HighlightSymbolTableBuilder;
import org.sonar.javascript.highlighter.HighlighterVisitor;
import org.sonar.javascript.metrics.MetricsVisitor;
import org.sonar.javascript.metrics.NoSonarVisitor;
import org.sonar.javascript.parser.JavaScriptParserBuilder;
import org.sonar.javascript.se.SeChecksDispatcher;
import org.sonar.javascript.visitors.JavaScriptVisitorContext;
import org.sonar.plugins.javascript.api.CustomJavaScriptRulesDefinition;
import org.sonar.plugins.javascript.api.CustomRuleRepository;
import org.sonar.plugins.javascript.api.JavaScriptCheck;
import org.sonar.plugins.javascript.api.tree.ScriptTree;
import org.sonar.plugins.javascript.api.tree.Tree;
import org.sonar.plugins.javascript.api.visitors.FileIssue;
import org.sonar.plugins.javascript.api.visitors.Issue;
import org.sonar.plugins.javascript.api.visitors.LineIssue;
import org.sonar.plugins.javascript.api.visitors.PreciseIssue;
import org.sonar.plugins.javascript.api.visitors.TreeVisitor;
import org.sonar.plugins.javascript.api.visitors.TreeVisitorContext;
import org.sonarsource.analyzer.commons.ProgressReport;

import static org.sonar.plugins.javascript.JavaScriptPlugin.DEPRECATED_ESLINT_PROPERTY;
import static org.sonar.plugins.javascript.JavaScriptPlugin.ESLINT_REPORT_PATHS;

public class JavaScriptSensor implements Sensor {

  private static final Logger LOG = Loggers.get(JavaScriptSensor.class);

  private final JavaScriptChecks checks;
  private final FileLinesContextFactory fileLinesContextFactory;
  private final FileSystem fileSystem;
  private final NoSonarFilter noSonarFilter;
  private final FilePredicate mainFilePredicate;
  private final ActionParser<Tree> parser;
  private final ActionParser<Tree> vueParser;
  // parsingErrorRuleKey equals null if ParsingErrorCheck is not activated
  private RuleKey parsingErrorRuleKey = null;
  private HashMap<String, FileAnalysis> analysisState = new HashMap<>();
  private long parsingTime = 0;
  private long visitorTime = 0;
  private long highlightingTime = 0;

  public JavaScriptSensor(
    CheckFactory checkFactory, FileLinesContextFactory fileLinesContextFactory, FileSystem fileSystem, NoSonarFilter noSonarFilter) {
    this(checkFactory, fileLinesContextFactory, fileSystem, noSonarFilter, null, null);
  }

  /**
   * This constructor is necessary for Pico container to correctly instantiate sensor with custom rules loaded via {@link CustomJavaScriptRulesDefinition}
   * See plugin integration tests
   */
  public JavaScriptSensor(
    CheckFactory checkFactory, FileLinesContextFactory fileLinesContextFactory, FileSystem fileSystem, NoSonarFilter noSonarFilter,
    @Nullable CustomJavaScriptRulesDefinition[] customRulesDefinition) {
    this(checkFactory, fileLinesContextFactory, fileSystem, noSonarFilter, customRulesDefinition, null);
  }

  /**
   * This constructor is necessary for Pico container to correctly instantiate sensor with custom rules loaded via {@link CustomRuleRepository}
   * See plugin integration tests
   */
  public JavaScriptSensor(
    CheckFactory checkFactory, FileLinesContextFactory fileLinesContextFactory, FileSystem fileSystem, NoSonarFilter noSonarFilter,
    @Nullable CustomRuleRepository[] customRuleRepositories) {
    this(checkFactory, fileLinesContextFactory, fileSystem, noSonarFilter, null, customRuleRepositories);
  }

  public JavaScriptSensor(
    CheckFactory checkFactory, FileLinesContextFactory fileLinesContextFactory, FileSystem fileSystem, NoSonarFilter noSonarFilter,
    @Nullable CustomJavaScriptRulesDefinition[] customRulesDefinition,
    @Nullable CustomRuleRepository[] customRuleRepositories) {
    this.checks = JavaScriptChecks.createJavaScriptCheck(checkFactory)
      .addChecks(CheckList.REPOSITORY_KEY, CheckList.getChecks())
      .addCustomChecks(customRulesDefinition, customRuleRepositories);
    this.fileLinesContextFactory = fileLinesContextFactory;
    this.fileSystem = fileSystem;
    this.noSonarFilter = noSonarFilter;
    this.mainFilePredicate = fileSystem.predicates().and(
      fileSystem.predicates().hasType(InputFile.Type.MAIN),
      fileSystem.predicates().hasLanguage(JavaScriptLanguage.KEY));
    this.parser = JavaScriptParserBuilder.createParser();
    this.vueParser = JavaScriptParserBuilder.createVueParser();
  }

  @VisibleForTesting
  protected void analyseFiles(
    SensorContext context, List<TreeVisitor> treeVisitors, Iterable<InputFile> inputFiles,
    ProductDependentExecutor executor, ProgressReport progressReport
  ) {
    boolean success = false;
    try {
      for (InputFile inputFile : inputFiles) {
        if (context.isCancelled()) {
          throw new CancellationException("Analysis interrupted because the SensorContext is in cancelled state");
        }
        analyse(context, inputFile, executor, treeVisitors);
        progressReport.nextFile();
      }
      success = true;
    } catch (CancellationException e) {
      // do not propagate the exception
      LOG.debug(e.toString());
    } finally {
      stopProgressReport(progressReport, success);
    }
  }

  private static void stopProgressReport(ProgressReport progressReport, boolean success) {
    if (success) {
      progressReport.stop();
    } else {
      progressReport.cancel();
    }
  }

  private void analyse(SensorContext sensorContext, InputFile inputFile, ProductDependentExecutor executor, List<TreeVisitor> visitors) {
    ActionParser<Tree> currentParser = this.parser;
    if (inputFile.filename().endsWith(".vue")) {
      currentParser = this.vueParser;
    }
    BigInteger encodedFileContent = null;
    try {
      MessageDigest fileContentDigest = MessageDigest.getInstance("SHA-256");
      encodedFileContent = new BigInteger(1, fileContentDigest.digest(inputFile.contents().getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException | IOException e) {
      LOG.debug("Couldn't create hash for file " + inputFile.filename(), e);
    }

    ScriptTree scriptTree;

    try {
      boolean cpdTokenAlreadySaved = false;
      boolean highlightingTokenAlreadySaved = false;
      long startTimeParsing = System.nanoTime();
      scriptTree = (ScriptTree) currentParser.parse(inputFile.contents());
      JavaScriptVisitorContext context = new JavaScriptVisitorContext(scriptTree, inputFile, sensorContext.config());
      long endTimeParsing = System.nanoTime();
      parsingTime += (endTimeParsing - startTimeParsing);
      FileAnalysis fileAnalysis = analysisState.get(inputFile.uri().getPath());
      if (fileAnalysis != null && fileAnalysis.encodedFileContent.equals(encodedFileContent)) {
        long startTimeVisitors = System.nanoTime();
        for (TreeVisitor visitor : visitors) {
          if (visitor instanceof CpdVisitor) {
            if (fileAnalysis.cpdTokens == null || fileAnalysis.cpdTokens.isEmpty()) {
              visitor.scanTree(context);
              fileAnalysis.cpdTokens = ((CpdVisitor) visitor).getTokens();
              cpdTokenAlreadySaved = true;
            }
          } else if (visitor instanceof HighlighterVisitor) {
            if (fileAnalysis.highlightingTokens == null || fileAnalysis.highlightingTokens.isEmpty()) {
              visitor.scanTree(context);
              fileAnalysis.highlightingTokens = ((HighlighterVisitor) visitor).getHighlightingTokens();
              highlightingTokenAlreadySaved = true;
            }
          } else if (!(visitor instanceof JavaScriptCheck)) {
            visitor.scanTree(context);
          }
        }
        long endTimeVisitors = System.nanoTime();
        visitorTime += (endTimeVisitors - startTimeVisitors);
        saveIssue(sensorContext, fileAnalysis.issues, inputFile);
        // CPD
        NewCpdTokens newCpdTokens = sensorContext.newCpdTokens().onFile(inputFile);
        fileAnalysis.cpdTokens.forEach(cpdToken -> {
          TextRange textRange = inputFile.newRange(cpdToken.startLine, cpdToken.startLineOffset, cpdToken.endLine, cpdToken.endLineOffset);
          newCpdTokens.addToken(textRange, cpdToken.image);
        });
        if (!cpdTokenAlreadySaved && !sensorContext.runtime().getProduct().equals(SonarProduct.SONARLINT)) {
          newCpdTokens.save();
        }
        // HIGHLIGHTING
        NewHighlighting newHighlighting = sensorContext.newHighlighting().onFile(inputFile);
        fileAnalysis.highlightingTokens.forEach(highlightToken ->
          newHighlighting.highlight(highlightToken.startLine, highlightToken.startLineOffset, highlightToken.endLine, highlightToken.endLineOffset, highlightToken.type));
        if (!highlightingTokenAlreadySaved && !sensorContext.runtime().getProduct().equals(SonarProduct.SONARLINT)) {
          newHighlighting.save();
        }
        // NOSONAR LINES
        noSonarFilter.noSonarInFile(inputFile, fileAnalysis.noSonarLines);
        long startTimeHighlighting = System.nanoTime();
        executor.highlightSymbols(inputFile, context);
        long endTimeHighlighting = System.nanoTime();
        highlightingTime += (endTimeHighlighting - startTimeHighlighting);
        return;
      }
      scanFile(sensorContext, inputFile, executor, visitors, scriptTree, encodedFileContent);
    } catch (RecognitionException e) {
      checkInterrupted(e);
      LOG.error("Unable to parse file: " + inputFile.uri());
      LOG.error(e.getMessage());
      processRecognitionException(e, sensorContext, inputFile);
    } catch (Exception e) {
      checkInterrupted(e);
      processException(e, sensorContext, inputFile);
      LOG.error("Unable to analyse file: " + inputFile.uri(), e);
    }
  }

  private static void checkInterrupted(Exception e) {
    Throwable cause = Throwables.getRootCause(e);
    if (cause instanceof InterruptedException || cause instanceof InterruptedIOException) {
      throw new AnalysisException("Analysis cancelled", e);
    }
  }

  private void processRecognitionException(RecognitionException e, SensorContext sensorContext, InputFile inputFile) {
    if (parsingErrorRuleKey != null) {
      NewIssue newIssue = sensorContext.newIssue();

      NewIssueLocation primaryLocation = newIssue.newLocation()
        .message(ParsingErrorCheck.MESSAGE)
        .on(inputFile)
        .at(inputFile.selectLine(e.getLine()));

      newIssue
        .forRule(parsingErrorRuleKey)
        .at(primaryLocation)
        .save();
    }

    sensorContext.newAnalysisError()
      .onFile(inputFile)
      .at(inputFile.newPointer(e.getLine(), 0))
      .message(e.getMessage())
      .save();

  }

  private static void processException(Exception e, SensorContext sensorContext, InputFile inputFile) {
    sensorContext.newAnalysisError()
      .onFile(inputFile)
      .message(e.getMessage())
      .save();
  }

  private void scanFile(SensorContext sensorContext, InputFile inputFile, ProductDependentExecutor executor, List<TreeVisitor> visitors, ScriptTree scriptTree, @CheckForNull BigInteger encodedFileContent) {
    JavaScriptVisitorContext context = new JavaScriptVisitorContext(scriptTree, inputFile, sensorContext.config());
    List<Issue> fileIssues = new ArrayList<>();
    List<CpdVisitor.CpdToken> cpdTokens = new ArrayList<>();
    List<HighlighterVisitor.HighlightToken> highlightingTokens = new ArrayList<>();
    Set<Integer> noSonarLines = new HashSet<>();
    for (TreeVisitor visitor : visitors) {
      if (visitor instanceof JavaScriptCheck) {
        fileIssues.addAll(((JavaScriptCheck) visitor).scanFile(context));
      } else if (visitor instanceof CpdVisitor) {
        visitor.scanTree(context);
        cpdTokens = ((CpdVisitor) visitor).getTokens();
      } else if (visitor instanceof HighlighterVisitor) {
        visitor.scanTree(context);
        highlightingTokens = ((HighlighterVisitor) visitor).getHighlightingTokens();
      } else if (visitor instanceof NoSonarVisitor) {
        visitor.scanTree(context);
        noSonarLines = ((NoSonarVisitor) visitor).getNoSonarLines();
      } else {
        visitor.scanTree(context);
      }
    }
    List<SerializableIssue> serializableIssues = getSerializableIssues(fileIssues);
    if (encodedFileContent != null) {
      analysisState.put(inputFile.uri().getPath(), new FileAnalysis(encodedFileContent, serializableIssues, cpdTokens, highlightingTokens, noSonarLines));
    }
    saveIssue(sensorContext, serializableIssues, inputFile);
    executor.highlightSymbols(inputFile, context);
  }

  private List<SerializableIssue> getSerializableIssues(List<Issue> fileIssues) {
    List<SerializableIssue> serializableIssues;
    serializableIssues = fileIssues.stream()
      .map(issue -> {
        RuleKey ruleKey = ruleKey(issue.check());
        SerializableIssue serializableIssue = new SerializableIssue();
        serializableIssue.ruleKey = ruleKey;
        serializableIssue.cost = issue.cost();
        if (issue instanceof FileIssue) {
          serializableIssue.message = ((FileIssue) issue).message();
        } else if (issue instanceof LineIssue) {
          serializableIssue.message = ((LineIssue) issue).message();
          serializableIssue.line = ((LineIssue) issue).line();
        } else {
          PreciseIssue preciseIssue = (PreciseIssue) issue;
          serializableIssue.message = preciseIssue.primaryLocation().message();
          serializableIssue.line = preciseIssue.primaryLocation().startLine();
          serializableIssue.column = preciseIssue.primaryLocation().startLineOffset();
          serializableIssue.endLine = preciseIssue.primaryLocation().endLine();
          serializableIssue.endColumn = preciseIssue.primaryLocation().endLineOffset();
          serializableIssue.secondaryLocations = preciseIssue.secondaryLocations().stream().map(secondary -> {
            SecondaryIssueLocation secondaryIssueLocation = new SecondaryIssueLocation();
            secondaryIssueLocation.line = secondary.startLine();
            secondaryIssueLocation.column = secondary.startLineOffset();
            secondaryIssueLocation.endLine = secondary.endLine();
            secondaryIssueLocation.endColumn = secondary.endLineOffset();
            secondaryIssueLocation.message = secondary.message();
            return secondaryIssueLocation;
          }).collect(Collectors.toList());
        }
        return serializableIssue;
      }).collect(Collectors.toList());
    return serializableIssues;
  }

  private void saveIssue(SensorContext context, List<SerializableIssue> issues, InputFile file) {

    issues.forEach(issue -> {
      NewIssue newIssue = context.newIssue();
      NewIssueLocation location = newIssue.newLocation()
        .message(issue.message)
        .on(file);

      if (issue.endLine != null) {
        location.at(file.newRange(issue.line, issue.column, issue.endLine, issue.endColumn));
      } else if (issue.line != null) {
        location.at(file.selectLine(issue.line));
      }

      issue.secondaryLocations.forEach(secondary -> {
        NewIssueLocation newIssueLocation = newSecondaryLocation(file, newIssue, secondary);
        if (newIssueLocation != null) {
          newIssue.addLocation(newIssueLocation);
        }
      });


      if (issue.cost != null) {
        newIssue.gap(issue.cost);
      }
      newIssue.at(location)
        .forRule(issue.ruleKey)
        .save();
    });
  }

  private static NewIssueLocation newSecondaryLocation(InputFile inputFile, NewIssue issue, SecondaryIssueLocation location) {
    NewIssueLocation newIssueLocation = issue.newLocation().on(inputFile);

    if (location.line != null && location.endLine != null && location.column != null && location.endColumn != null) {
      newIssueLocation.at(inputFile.newRange(location.line, location.column, location.endLine, location.endColumn));
      if (location.message != null) {
        newIssueLocation.message(location.message);
      }
      return newIssueLocation;
    }
    return null;
  }

  private RuleKey ruleKey(JavaScriptCheck check) {
    Preconditions.checkNotNull(check);
    RuleKey ruleKey = checks.ruleKeyFor(check);
    if (ruleKey == null) {
      throw new IllegalStateException("No rule key found for a rule");
    }
    return ruleKey;
  }

  @Override
  public void describe(SensorDescriptor descriptor) {
    descriptor
      .onlyOnLanguage(JavaScriptLanguage.KEY)
      .name("SonarJS")
      .onlyOnFileType(Type.MAIN);
  }

  @Override
  public void execute(SensorContext context) {
    checkDeprecatedEslintProperty(context);

    ProductDependentExecutor executor = createProductDependentExecutor(context);

    List<TreeVisitor> treeVisitors = Lists.newArrayList();

    // it's important to have an order here:
    // NoSonarVisitor (part of executor.getProductDependentTreeVisitors()) should go before all checks
    treeVisitors.addAll(executor.getProductDependentTreeVisitors());
    treeVisitors.add(new SeChecksDispatcher(checks.seChecks()));
    treeVisitors.addAll(checks.visitorChecks());

    for (TreeVisitor check : treeVisitors) {
      if (check instanceof ParsingErrorCheck) {
        parsingErrorRuleKey = checks.ruleKeyFor((JavaScriptCheck) check);
        break;
      }
    }

    Iterable<InputFile> inputFiles = fileSystem.inputFiles(mainFilePredicate);
    Collection<String> files = StreamSupport.stream(inputFiles.spliterator(), false)
      .map(InputFile::toString)
      .collect(Collectors.toList());

    ProgressReport progressReport = new ProgressReport("Report about progress of Javascript analyzer", TimeUnit.SECONDS.toMillis(10));
    progressReport.start(files);
    // Load analysis state
    Gson gson = new Gson();
    try {
      java.lang.reflect.Type type = new TypeToken<HashMap<String, FileAnalysis>>() {
      }.getType();
      JsonReader reader = new JsonReader(new FileReader("analysisStateJavaScriptSensor.json"));
      HashMap<String, FileAnalysis> loadedAnalysisState = gson.fromJson(reader, type);
      if (loadedAnalysisState != null) {
        this.analysisState = loadedAnalysisState;
      }
    } catch (FileNotFoundException e) {
      LOG.debug("Cannot load analysisState file");
    }

    analyseFiles(context, treeVisitors, inputFiles, executor, progressReport);
    storeAnalysisState(gson);
    LOG.info("Parsing time = " + parsingTime  / 1000000 + " ms");
    LOG.info("Visitors time = " + visitorTime  / 1000000 + " ms");
    LOG.info("Highlighting time = " + highlightingTime  / 1000000 + " ms");
  }

  private void storeAnalysisState(Gson gson) {
    try {
      FileWriter writer = new FileWriter("analysisStateJavaScriptSensor.json");
      gson.toJson(this.analysisState, writer);
      writer.flush();
      writer.close();
    } catch (IOException e) {
      LOG.debug("Cannot store analysisState file");
    }
  }

  /**
   * Check if property consumed by SonarTS to import ESLint issues is set
   */
  private static void checkDeprecatedEslintProperty(SensorContext context) {
    if (ArrayUtils.isNotEmpty(context.config().getStringArray(DEPRECATED_ESLINT_PROPERTY))) {
      LOG.warn("Property '{}' is deprecated, use '{}'.", DEPRECATED_ESLINT_PROPERTY, ESLINT_REPORT_PATHS);
    }
  }

  private ProductDependentExecutor createProductDependentExecutor(SensorContext context) {
    if (isSonarLint(context)) {
      return new SonarLintProductExecutor(noSonarFilter, context);
    }
    return new SonarQubeProductExecutor(context, noSonarFilter, fileLinesContextFactory);
  }

  @VisibleForTesting
  protected interface ProductDependentExecutor {
    List<TreeVisitor> getProductDependentTreeVisitors();

    void highlightSymbols(InputFile inputFile, TreeVisitorContext treeVisitorContext);
  }

  private static class SonarQubeProductExecutor implements ProductDependentExecutor {
    private final SensorContext context;
    private final NoSonarFilter noSonarFilter;
    private final FileLinesContextFactory fileLinesContextFactory;

    SonarQubeProductExecutor(SensorContext context, NoSonarFilter noSonarFilter, FileLinesContextFactory fileLinesContextFactory) {
      this.context = context;
      this.noSonarFilter = noSonarFilter;
      this.fileLinesContextFactory = fileLinesContextFactory;
    }

    @Override
    public List<TreeVisitor> getProductDependentTreeVisitors() {
      boolean ignoreHeaderComments = ignoreHeaderComments(context);

      MetricsVisitor metricsVisitor = new MetricsVisitor(
        context,
        ignoreHeaderComments,
        fileLinesContextFactory);

      return Arrays.asList(
        metricsVisitor,
        new NoSonarVisitor(noSonarFilter, ignoreHeaderComments),
        new HighlighterVisitor(context),
        new CpdVisitor(context));
    }

    @Override
    public void highlightSymbols(InputFile inputFile, TreeVisitorContext treeVisitorContext) {
      NewSymbolTable newSymbolTable = context.newSymbolTable().onFile(inputFile);
      HighlightSymbolTableBuilder.build(newSymbolTable, treeVisitorContext);
    }
  }

  @VisibleForTesting
  protected static class SonarLintProductExecutor implements ProductDependentExecutor {
    private final NoSonarFilter noSonarFilter;
    private final SensorContext context;

    SonarLintProductExecutor(NoSonarFilter noSonarFilter, SensorContext context) {
      this.noSonarFilter = noSonarFilter;
      this.context = context;
    }

    @Override
    public List<TreeVisitor> getProductDependentTreeVisitors() {
      return ImmutableList.of(new NoSonarVisitor(noSonarFilter, ignoreHeaderComments(context)));
    }

    @Override
    public void highlightSymbols(InputFile inputFile, TreeVisitorContext treeVisitorContext) {
      // unnecessary in SonarLint context
    }
  }

  private static boolean ignoreHeaderComments(SensorContext context) {
    return context.config().getBoolean(JavaScriptPlugin.IGNORE_HEADER_COMMENTS).orElse(JavaScriptPlugin.IGNORE_HEADER_COMMENTS_DEFAULT_VALUE);
  }

  private static boolean isSonarLint(SensorContext context) {
    return context.runtime().getProduct() == SonarProduct.SONARLINT;
  }

  static class AnalysisException extends RuntimeException {
    AnalysisException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static class FileAnalysis {
    BigInteger encodedFileContent;
    List<SerializableIssue> issues;
    List<CpdVisitor.CpdToken> cpdTokens;
    List<HighlighterVisitor.HighlightToken> highlightingTokens;
    Set<Integer> noSonarLines;

    FileAnalysis(BigInteger encodedFileContent, List<SerializableIssue> issues, List<CpdVisitor.CpdToken> cpdTokens, List<HighlighterVisitor.HighlightToken> highlightingTokens, Set<Integer> noSonarLines) {
      this.encodedFileContent = encodedFileContent;
      this.issues = issues;
      this.cpdTokens = cpdTokens;
      this.highlightingTokens = highlightingTokens;
      this.noSonarLines = noSonarLines;
    }
  }

  static class SerializableIssue {
    Integer line;
    Integer column;
    Integer endLine;
    Integer endColumn;
    String message;
    RuleKey ruleKey;
    List<SecondaryIssueLocation> secondaryLocations = new ArrayList<>();
    Double cost;
  }

  static class SecondaryIssueLocation {
    Integer line;
    Integer column;
    Integer endLine;
    Integer endColumn;
    String message;
  }

}
