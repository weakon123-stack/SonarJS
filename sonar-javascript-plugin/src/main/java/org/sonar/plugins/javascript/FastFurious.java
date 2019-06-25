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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.sonar.api.batch.sensor.highlighting.TypeOfText;
import org.sonar.api.rule.RuleKey;
import org.sonar.javascript.cpd.CpdVisitor;
import org.sonar.javascript.highlighter.HighlightSymbolTableBuilder;
import org.sonar.javascript.highlighter.HighlighterVisitor;

public class FastFurious {

  public static class FileAnalysis {
    List<HighlightSymbolTableBuilder.SerializableSymbol> symbolsToHighlight;
    Set<Integer> executableLines;
    Set<Integer> linesOfCode;
    Map<String, String> metrics;
    BigInteger encodedFileContent;
    List<SerializableIssue> issues;
    List<CpdVisitor.CpdToken> cpdTokens;
    List<HighlighterVisitor.HighlightToken> highlightingTokens;
    Set<Integer> noSonarLines;

    FileAnalysis(BigInteger encodedFileContent, List<SerializableIssue> issues, List<CpdVisitor.CpdToken> cpdTokens, List<HighlighterVisitor.HighlightToken> highlightingTokens, Set<Integer> noSonarLines, Map<String, String> metrics, Set<Integer> linesOfCode, Set<Integer> executableLines, List<HighlightSymbolTableBuilder.SerializableSymbol> serializableSymbols) {
      this.encodedFileContent = encodedFileContent;
      this.issues = issues;
      this.cpdTokens = cpdTokens;
      this.highlightingTokens = highlightingTokens;
      this.noSonarLines = noSonarLines;
      this.metrics = metrics;
      this.linesOfCode = linesOfCode;
      this.executableLines = executableLines;
      this.symbolsToHighlight = serializableSymbols;
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
    Double cost = 0.;
  }

  static class SecondaryIssueLocation {
    Integer line;
    Integer column;
    Integer endLine;
    Integer endColumn;
    String message;
  }


  public static void write(File file, Map<String, FileAnalysis> analysisState) {
    try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(file.toPath()))) {
      writeState(out, analysisState);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void writeState(OutputStream stream, Map<String, FileAnalysis> state) throws IOException {
    DataOutputStream out = new DataOutputStream(stream);
    out.writeUTF("STATE");

    // files
    out.writeInt(state.size());
    for (Map.Entry<String, FileAnalysis> entry : state.entrySet()) {
      out.writeUTF(entry.getKey());
      // FileAnalysis
      FileAnalysis fileAnalysis = entry.getValue();

      writeSymbolsToHighlight(out, fileAnalysis);

      // executable lines
      out.writeInt(fileAnalysis.executableLines.size());
      for (int executableLine : fileAnalysis.executableLines) {
        out.writeInt(executableLine);
      }

      // lines of code
      out.writeInt(fileAnalysis.linesOfCode.size());
      for (int executableLine : fileAnalysis.linesOfCode) {
        out.writeInt(executableLine);
      }

      // metrics
      out.writeInt(fileAnalysis.metrics.size());
      for (Map.Entry<String,String> metricEntry : fileAnalysis.metrics.entrySet()) {
        out.writeUTF(metricEntry.getKey());
        out.writeUTF(metricEntry.getValue());
      }

      // hash
      out.writeUTF(fileAnalysis.encodedFileContent.toString());

      // issues
      writeIssues(out, fileAnalysis);

      // cpd tokens
      out.writeInt(fileAnalysis.cpdTokens.size());
      for (CpdVisitor.CpdToken cpdToken : fileAnalysis.cpdTokens) {
        for (int point : cpdToken.l) {
          out.writeInt(point);
        }
        out.writeUTF(cpdToken.i);
      }

      // highlighting tokens
      out.writeInt(fileAnalysis.highlightingTokens.size());
      for (HighlighterVisitor.HighlightToken highlightingToken : fileAnalysis.highlightingTokens) {
        for (int point : highlightingToken.l) {
          out.writeInt(point);
        }
        out.writeUTF(highlightingToken.t.cssClass());
      }

      // nosonar lines
      out.writeInt(fileAnalysis.noSonarLines.size());
      for (Integer noSonarLine : fileAnalysis.noSonarLines) {
        out.writeInt(noSonarLine);
      }
    }
  }

  private static void writeIssues(DataOutputStream out, FileAnalysis fileAnalysis) throws IOException {
    out.writeInt(fileAnalysis.issues.size());
    for (SerializableIssue issue : fileAnalysis.issues) {
      if (issue.line == null) {
        issue.line = -1;
      }
      out.writeInt(issue.line);
      if (issue.column == null) {
        issue.column = -1;
      }
      out.writeInt(issue.column);
      if (issue.endLine == null) {
        issue.endLine = -1;
      }
      out.writeInt(issue.endLine);
      if (issue.endColumn == null) {
        issue.endColumn = -1;
      }
      out.writeInt(issue.endColumn);
      out.writeUTF(issue.message);
      out.writeUTF(issue.ruleKey.toString());
      out.writeInt(issue.secondaryLocations.size());
      for (SecondaryIssueLocation secondaryIssueLocation : issue.secondaryLocations) {
        if (secondaryIssueLocation.line == null) {
          secondaryIssueLocation.line = -1;
        }
        out.writeInt(secondaryIssueLocation.line);
        if (secondaryIssueLocation.column == null) {
          secondaryIssueLocation.column = -1;
        }
        out.writeInt(secondaryIssueLocation.column);
        if (secondaryIssueLocation.endLine == null) {
          secondaryIssueLocation.endLine = -1;
        }
        out.writeInt(secondaryIssueLocation.endLine);
        if (secondaryIssueLocation.endColumn == null) {
          secondaryIssueLocation.endColumn = -1;
        }
        out.writeInt(secondaryIssueLocation.endColumn);
        if (secondaryIssueLocation.message == null) {
          secondaryIssueLocation.message = "NULL";
        }
        out.writeUTF(secondaryIssueLocation.message);
      }
      if (issue.cost == null) {
        issue.cost = -1.;
      }
      out.writeDouble(issue.cost);
    }
  }

  private static void writeSymbolsToHighlight(DataOutputStream out, FileAnalysis fileAnalysis) throws IOException {
    List<HighlightSymbolTableBuilder.SerializableSymbol> symbolsToHighlight = fileAnalysis.symbolsToHighlight;
    out.writeInt(symbolsToHighlight.size());
    for (HighlightSymbolTableBuilder.SerializableSymbol symbol : symbolsToHighlight) {
      // symbol location
      for (int point : symbol.l) {
        out.writeInt(point);
      }
      // references
      out.writeInt(symbol.r.size());
      for (HighlightSymbolTableBuilder.SymbolReference reference : symbol.r) {
        for (int point : reference.l) {
          out.writeInt(point);
        }
      }
    }
  }

  public static Map<String, FileAnalysis> read(File file) {
    try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
      return readState(in);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HashMap<String, FileAnalysis> readState(InputStream stream) throws IOException {
    DataInputStream in = new DataInputStream(stream);
    if (!"STATE".equals(in.readUTF())) {
      throw new IOException();
    }

    HashMap<String, FileAnalysis> analysisState = new HashMap<>();
    int filesSize = in.readInt();
    for (int i = 0; i < filesSize; i++) {
      String key = in.readUTF();
      // symbols to highlight
      List<HighlightSymbolTableBuilder.SerializableSymbol> symbolsToHighlight = readSymbolsToHighlight(in);

      // executable lines
      int executableLinesSize = in.readInt();
      Set<Integer> executableLines = new HashSet<>();
      for (int j = 0; j < executableLinesSize; j++) {
        executableLines.add(in.readInt());
      }

      // lines of code
      int linesOfCodeSize = in.readInt();
      Set<Integer> linesOfCode = new HashSet<>();
      for (int j = 0; j < linesOfCodeSize; j++) {
        linesOfCode.add(in.readInt());
      }

      // metrics
      int metricsSize = in.readInt();
      Map<String, String> metrics = new HashMap<>();
      for (int j = 0; j < metricsSize; j++) {
        metrics.put(in.readUTF(), in.readUTF());
      }

      // hash
      String hash = in.readUTF();
      BigInteger encodedFile = new BigInteger(hash);

      // issues
      List<SerializableIssue> serializableIssues = readIssues(in);

      // cpd tokens
      int cpdTokensSize = in.readInt();
      List<CpdVisitor.CpdToken> cpdTokens = new ArrayList<>();
      for (int j = 0; j < cpdTokensSize; j++) {
        int line = in.readInt();
        int column = in.readInt();
        int endline = in.readInt();
        int endColumn = in.readInt();
        String image = in.readUTF();
        cpdTokens.add(new CpdVisitor.CpdToken(line, column, endline, endColumn, image));
      }

      // highlighting tokens
      int highlightingSize = in.readInt();
      List<HighlighterVisitor.HighlightToken> highlightTokens = new ArrayList<>();
      for (int j = 0; j < highlightingSize; j++) {
        int line = in.readInt();
        int column = in.readInt();
        int endline = in.readInt();
        int endColumn = in.readInt();
        String cssClass = in.readUTF();
        highlightTokens.add(new HighlighterVisitor.HighlightToken(line, column, endline, endColumn, TypeOfText.forCssClass(cssClass)));
      }

      // nosonar lines
      int noSonarLinesSize = in.readInt();
      Set<Integer> noSonarLines = new HashSet<>();
      for (int j = 0; j < noSonarLinesSize; j++) {
        noSonarLines.add(in.readInt());
      }

      analysisState.put(key, new FileAnalysis(encodedFile, serializableIssues, cpdTokens, highlightTokens, noSonarLines, metrics, linesOfCode, executableLines, symbolsToHighlight));
    }
    return analysisState;
  }

  private static List<SerializableIssue> readIssues(DataInputStream in) throws IOException {
    int issuesSize = in.readInt();
    List<SerializableIssue> serializableIssues = new ArrayList<>();
    for (int j = 0; j < issuesSize; j++) {
      SerializableIssue serializableIssue = new SerializableIssue();
      serializableIssue.line = in.readInt();
      if (serializableIssue.line == -1) {
        serializableIssue.line = null;
      }
      serializableIssue.column = in.readInt();
      if (serializableIssue.column == -1) {
        serializableIssue.column = null;
      }
      serializableIssue.endLine = in.readInt();
      if (serializableIssue.endLine == -1) {
        serializableIssue.endLine = null;
      }
      serializableIssue.endColumn = in.readInt();
      if (serializableIssue.endColumn == -1) {
        serializableIssue.endColumn = null;
      }
      serializableIssue.message = in.readUTF();
      String ruleKey = in.readUTF();
      serializableIssue.ruleKey = RuleKey.parse(ruleKey);
      int secondariesSize = in.readInt();
      serializableIssue.secondaryLocations = new ArrayList<>();
      for (int k = 0; k < secondariesSize; k++) {
        SecondaryIssueLocation secondaryIssueLocation = new SecondaryIssueLocation();
        secondaryIssueLocation.line = in.readInt();
        if (secondaryIssueLocation.line == -1) {
          serializableIssue.line = null;
        }
        secondaryIssueLocation.column = in.readInt();
        if (secondaryIssueLocation.column == -1) {
          serializableIssue.column = null;
        }
        secondaryIssueLocation.endLine = in.readInt();
        if (secondaryIssueLocation.endLine == -1) {
          serializableIssue.endLine = null;
        }
        secondaryIssueLocation.endColumn = in.readInt();
        if (secondaryIssueLocation.endColumn == -1) {
          serializableIssue.endColumn = null;
        }
        secondaryIssueLocation.message = in.readUTF();
        if (secondaryIssueLocation.message.equals("NULL")) {
          secondaryIssueLocation.message = null;
        }
        serializableIssue.secondaryLocations.add(secondaryIssueLocation);
      }
      serializableIssue.cost = in.readDouble();
      if (serializableIssue.cost == -1.) {
        serializableIssue.cost = null;
      }
      serializableIssues.add(serializableIssue);
    }
    return serializableIssues;
  }

  private static List<HighlightSymbolTableBuilder.SerializableSymbol> readSymbolsToHighlight(DataInputStream in) throws IOException {
    int symbolsSize = in.readInt();
    List<HighlightSymbolTableBuilder.SerializableSymbol> symbolsToHighlight = new ArrayList<>();
    for (int j = 0; j < symbolsSize; j++) {
      int line = in.readInt();
      int column = in.readInt();
      int endline = in.readInt();
      int endColumn = in.readInt();
      HighlightSymbolTableBuilder.SerializableSymbol symbol = new HighlightSymbolTableBuilder.SerializableSymbol(new int[] {line, column, endline, endColumn});
      int referencesSize = in.readInt();
      for (int k = 0; k < referencesSize; k++) {
        int refline = in.readInt();
        int refcolumn = in.readInt();
        int refendline = in.readInt();
        int refendColumn = in.readInt();
        HighlightSymbolTableBuilder.SymbolReference reference = new HighlightSymbolTableBuilder.SymbolReference(new int[]{refline, refcolumn, refendline, refendColumn});
        symbol.r.add(reference);
      }
      symbolsToHighlight.add(symbol);
    }
    return symbolsToHighlight;
  }
}
