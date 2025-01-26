#include <iostream>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

vector<cpp_int> generateFibonacciLevels(int levels) {
    vector<cpp_int> fib;
    if (levels <= 0) return fib;
    fib.push_back(1);
    if (levels == 1) return fib;
    fib.push_back(1);
    for (int i = 2; i < levels; ++i) {
        fib.push_back(fib[i-1] + fib[i-2]);
    }
    return fib;
}

void printFibonacciDividedRange(const cpp_int& start, const cpp_int& end) {
    const int levels = 8;
    cpp_int range = end - start;
    if (range < 0) {
        cout << "Invalid range (start > end)." << endl;
        return;
    }

    vector<cpp_int> fib = generateFibonacciLevels(levels);
    cpp_int fibSum = 0;
    for (const auto& num : fib) fibSum += num;

    if (fibSum == 0) {
        cout << "Error: Fibonacci sum is zero." << endl;
        return;
    }

    vector<cpp_int> segmentSizes;
    cpp_int usedRange = 0;
    for (const auto& num : fib) {
        cpp_int segment = (num * range) / fibSum;
        segmentSizes.push_back(segment);
        usedRange += segment;
    }

    // Adjust for remainder
    cpp_int remainder = range - usedRange;
    if (remainder > 0) {
        segmentSizes.back() += remainder;
    }

    // Print segments
    cpp_int current = start;
    for (const auto& size : segmentSizes) {
        if (size <= 0) break;
        cpp_int next = current + size;
        if (next > end) next = end;
        cout << current << " to " << next << endl;
        current = next;
        if (current >= end) break;
    }
}

int main() {
    string start_str, end_str;
    cout << "Enter start: ";
    cin >> start_str;
    cout << "Enter end: ";
    cin >> end_str;

    cpp_int start(start_str), end(end_str);
    printFibonacciDividedRange(start, end);
    return 0;
}