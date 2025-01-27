#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <signal.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <fstream>
#include <map>
#include <condition_variable>
#include <csignal>

using namespace std;
using namespace boost::multiprecision;

atomic<bool> should_stop(false);
condition_variable cv;
mutex global_mutex;

class CheckpointManager {
    mutex mtx;
    map<int, cpp_int> thread_positions;
    const string filename = "checkpoints.txt";

public:
    void save_checkpoint(int thread_id, cpp_int position) {
        {
            lock_guard<mutex> lock(mtx);
            thread_positions[thread_id] = position;
        }
        persist_checkpoints();
    }

    void persist_checkpoints() {
        lock_guard<mutex> lock(mtx);
        ofstream file(filename, ios::trunc);
        if (!file) {
            cerr << "Failed to open checkpoint file for writing" << endl;
            return;
        }
        for (const auto& [id, pos] : thread_positions) {
            file << id << " " << pos << "\n";
        }
    }

    map<int, cpp_int> load_checkpoints() {
        lock_guard<mutex> lock(mtx);
        map<int, cpp_int> checkpoints;
        ifstream file(filename);
        if (file) {
            int id;
            string pos_str;
            while (file >> id >> pos_str) {
                checkpoints[id] = cpp_int(pos_str);
            }
        }
        return checkpoints;
    }
};

void signal_handler(int signum) {
    cout << "\nReceived interrupt signal. Saving checkpoints..." << endl;
    should_stop = true;
    cv.notify_all();
}

class ParallelProcessor {
    cpp_int start_range;
    cpp_int end_range;
    int num_threads;
    CheckpointManager checkpoint_mgr;
    mutex cout_mutex;

    void process_chunk(int thread_id, cpp_int chunk_start, cpp_int chunk_end) {
        try {
            cpp_int current = chunk_start;
            while (current < chunk_end && !should_stop) {
                // Simulate work
                cpp_int result = (current * current) % 1000;

                // Save checkpoint every 1000 iterations
                if (current % 1000 == 0) {
                    checkpoint_mgr.save_checkpoint(thread_id, current);
                    {
                        lock_guard<mutex> lock(cout_mutex);
                        // cout << "Thread " << thread_id 
                        //      << " processed: " << current 
                        //      << " / " << chunk_end << endl;
                    }
                }
                current += 1;
            }

            // Save final position if not interrupted
            if (!should_stop) {
                checkpoint_mgr.save_checkpoint(thread_id, chunk_end);
            }
        }
        catch (const exception& e) {
            lock_guard<mutex> lock(cout_mutex);
            cerr << "Thread " << thread_id << " error: " << e.what() << endl;
        }
    }

public:
    ParallelProcessor(cpp_int start, cpp_int end, int _threads) 
        : start_range(start), 
          end_range(end), 
          num_threads(_threads) {}

    void run() {
        // Set up signal handler
        signal(SIGINT, signal_handler);

        vector<thread> threads;
        auto checkpoints = checkpoint_mgr.load_checkpoints();

        cpp_int range = end_range - start_range;
        cpp_int chunk_size = range / num_threads;

        cout << "Starting processing with " << num_threads << " threads" << endl;

        // Create and start threads
        for (int i = 0; i < num_threads; i++) {
            cpp_int chunk_start = start_range + (i * chunk_size);
            cpp_int chunk_end = (i == num_threads - 1) ? end_range 
                                                      : chunk_start + chunk_size;

            // Resume from checkpoint if exists
            if (checkpoints.count(i)) {
                chunk_start = max(chunk_start, checkpoints[i]);
                cout << "Thread " << i << " resuming from: " << chunk_start << endl;
            }

            if (chunk_start < chunk_end) {
                threads.emplace_back(&ParallelProcessor::process_chunk, this,
                                   i, chunk_start, chunk_end);
            }
        }

        // Wait for threads to complete
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        if (should_stop) {
            cout << "Processing interrupted. Checkpoints saved." << endl;
        } else {
            cout << "Processing completed successfully." << endl;
        }
    }
};

int main() {
    try {
        cpp_int start("0");
        cpp_int end("1000000000"); // One billion for example

        ParallelProcessor processor(start, end,2);
        processor.run();

        return 0;
    }
    catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }
}


