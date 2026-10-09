#include <bits/stdc++.h>
using namespace std;

// ARC207 C - M0
// Greedy invariant:
// Given the previous finalized block OR = prev, the next block should end at
// the earliest position where its OR becomes >= prev. Extending it further can
// only increase its OR and consume more elements, so it cannot improve any
// continuation. If the remaining suffix never reaches prev, it must be merged
// into the previous block and contributes no additional block.
int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if (!(cin >> N)) return 0;
    vector<unsigned int> A(N);
    for (auto &x : A) cin >> x;

    int ans = 1;
    unsigned int prev = A[0];
    int i = 1;
    while (i < N) {
        unsigned int cur = 0;
        while (i < N && cur < prev) {
            cur |= A[i];
            ++i;
        }
        if (cur >= prev) {
            ++ans;
            prev = cur;
        } else {
            break;
        }
    }
    cout << ans << '\n';
    return 0;
}
