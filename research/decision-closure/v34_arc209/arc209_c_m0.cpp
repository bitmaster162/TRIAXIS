#include <bits/stdc++.h>
using namespace std;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N, X, Q;
    if (!(cin >> N >> X >> Q)) return 0;
    vector<int> S(N + 1), P(N + 1);
    for (int i = 1; i <= N; ++i) cin >> S[i];
    for (int i = 1; i <= N; ++i) cin >> P[i];

    const int NEG = -1000000000;
    vector<int> dp(X + 2), ndp(X + 2), pref(X + 2), suf(X + 3);

    while (Q--) {
        int l, r;
        cin >> l >> r;

        fill(dp.begin(), dp.end(), NEG);
        dp[1] = 0;

        for (int i = l; i <= r; ++i) {
            pref[0] = NEG;
            for (int u = 1; u <= X; ++u) pref[u] = max(pref[u - 1], dp[u]);
            suf[X + 1] = NEG;
            for (int u = X; u >= 1; --u) suf[u] = max(suf[u + 1], dp[u]);

            fill(ndp.begin(), ndp.end(), NEG);
            for (int v = 1; v <= X; ++v) {
                int t = (S[i] + v - 1) / v; // smallest previous value u with u*v >= S_i
                int best = NEG;

                int last_nonqual = min(X, t - 1);
                if (last_nonqual >= 1) best = max(best, pref[last_nonqual]);

                if (t <= X && suf[t] > NEG / 2) {
                    best = max(best, suf[t] + P[i]);
                }
                ndp[v] = best;
            }
            dp.swap(ndp);
        }

        cout << *max_element(dp.begin() + 1, dp.begin() + X + 1) << '\n';
    }
    return 0;
}
