// bench_printer.cpp
#include "bench_printer.h"

Printer::Printer(bool debug) : debug_(debug) {}

void Printer::PrintMessage(const std::string &message) {
  if (debug_) {
    std::cout << PREFIX << message << std::endl;
  }
}

void Printer::PrintHeader(const std::string &header) {
  if (debug_) {
    const int totalWidth = 80;
    const int padding = 4;
    std::vector<std::string> lines =
        splitIntoLines(header, totalWidth - (padding * 2));
    std::cout << std::endl;
    std::cout << std::string(totalWidth, '=') << std::endl;
    for (const std::string &line : lines) {
      int paddingLeft = (totalWidth - line.length()) / 2;
      int paddingRight = totalWidth - line.length() - paddingLeft;
      std::cout << std::string(paddingLeft, ' ') + line +
                       std::string(paddingRight, ' ')
                << std::endl;
    }
    std::cout << std::string(totalWidth, '=') << std::endl;
  }
}

std::vector<std::string> Printer::splitIntoLines(const std::string &text,
                                                 int maxWidth) {
  std::vector<std::string> lines;
  std::string currentLine;
  std::string word;
  for (char c : text) {
    if (c == ' ') {
      if (currentLine.length() + word.length() + 1 <= maxWidth) {
        if (!currentLine.empty()) {
          currentLine += " ";
        }
        currentLine += word;
        word.clear();
      } else {
        lines.push_back(currentLine);
        currentLine = word;
        word.clear();
      }
    } else {
      word += c;
    }
  }
  if (!word.empty()) {
    if (!currentLine.empty() &&
        currentLine.length() + word.length() + 1 <= maxWidth) {
      if (!currentLine.empty()) {
        currentLine += " ";
      }
      currentLine += word;
    } else if (currentLine.empty()) {
      currentLine = word;
    } else {
      lines.push_back(currentLine);
      currentLine = word;
    }
  }
  if (!currentLine.empty()) {
    lines.push_back(currentLine);
  }
  return lines;
}
