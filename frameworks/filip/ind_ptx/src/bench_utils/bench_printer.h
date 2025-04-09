// bench_printer.h
#ifndef BENCH_PRINTER_H
#define BENCH_PRINTER_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

class Printer {
public:
    Printer(bool debug);

    void PrintMessage(const std::string &message);

    template<typename... Args>
    void PrintMessages(Args... args);

    template<typename... Args>
    void PrintFormatted(const std::string &format, Args... args);

    void PrintHeader(const std::string &header);

private:
    bool debug_;
    static constexpr const char *PREFIX = ">>> ";

    template<typename T>
    void PrintMessagesImpl(T arg) {
        std::cout << arg;
    }

    template<typename T, typename... Args>
    void PrintMessagesImpl(T arg, Args... args) {
        std::cout << arg;
        PrintMessagesImpl(args...);
    }

    template<typename... Args>
    void PrintFormattedImpl(const std::string &format, Args... args) {
        std::ostringstream oss;
        FormatHelper(oss, format, 0, args...);
        std::cout << oss.str();
    }

    template<typename... Args>
    void FormatHelper(std::ostringstream &oss, const std::string &format, size_t pos, Args... args) {
        if (pos >= format.length()) {
            return;
        }

        if (format[pos] == '%' && pos + 1 < format.length()) {
            if (format[pos + 1] == '%') {
                oss << '%';
                FormatHelper(oss, format, pos + 2, args...);
            } else {
                FormatArgs(oss, format[pos + 1], args...);
                FormatHelper(oss, format, pos + 2, args...);
            }
        } else {
            oss << format[pos];
            FormatHelper(oss, format, pos + 1, args...);
        }
    }

    template<typename T, typename... Args>
    void FormatArgs(std::ostringstream &oss, char specifier, T arg, Args... args) {
        switch (specifier) {
            case 'd':
                oss << std::dec << arg;
                break;
            case 'x':
                oss << std::hex << arg;
                break;
            case 'o':
                oss << std::oct << arg;
                break;
            case 'f':
                oss << std::fixed << std::setprecision(6) << arg;
                break;
            case 's':
                oss << arg;
                break;
            case 'c':
                oss << static_cast<char>(arg);
                break;
            default:
                oss << '%' << specifier; // Handle unknown specifier
        }
    }

    template<typename... Args>
    void FormatArgs(std::ostringstream &oss, char specifier) {
        oss << '%' << specifier; // Handle case where no argument is provided
    }

    static std::vector<std::string> splitIntoLines(const std::string &text, int maxWidth);
};

// Implementations of the template functions in the header
template<typename... Args>
void Printer::PrintMessages(Args... args) {
    if (debug_) {
        std::cout << PREFIX;
        PrintMessagesImpl(args...);
        std::cout << std::endl;
    }
}

template<typename... Args>
void Printer::PrintFormatted(const std::string &format, Args... args) {
    if (debug_) {
        std::cout << PREFIX;
        PrintFormattedImpl(format, args...);
        std::cout << std::endl;
    }
}

#endif // PRINTER_H
