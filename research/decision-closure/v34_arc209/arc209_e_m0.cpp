#include <bits/stdc++.h>
using namespace std;

static const long long MOD = 998244353;

long long modpow(long long a, long long e) {
    long long r = 1;
    while (e) {
        if (e & 1) r = r * a % MOD;
        a = a * a % MOD;
        e >>= 1;
    }
    return r;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    vector<pair<int,int>> qs(T);
    int maxN = 0;
    for (auto &[N,K] : qs) {
        cin >> N >> K;
        maxN = max(maxN, N);
    }

    vector<long long> fact(maxN + 3), ifact(maxN + 3);
    fact[0] = 1;
    for (int i = 1; i <= maxN + 2; ++i) fact[i] = fact[i - 1] * i % MOD;
    ifact[maxN + 2] = modpow(fact[maxN + 2], MOD - 2);
    for (int i = maxN + 2; i >= 1; --i) ifact[i - 1] = ifact[i] * i % MOD;
    const long long inv2 = (MOD + 1) / 2;

    unordered_map<unsigned long long, long long> memo;
    memo.reserve(T * 2 + 1);

    for (auto [N,K] : qs) {
        int c = N - K;
        unsigned long long key = (static_cast<unsigned long long>(N) << 20) ^ static_cast<unsigned long long>(c);
        auto itmemo = memo.find(key);
        if (itmemo != memo.end()) {
            cout << itmemo->second << '\n';
            continue;
        }

        long long ans = 0;
        if (3LL * c <= N) {
            int bmax = (N - c) / 2;
            for (int b = c; b <= bmax; ++b) {
                int a = N - c - b;
                if (a < b) continue;

                long long x = (a - b + 1) % MOD;
                long long y = (a - c + 2) % MOD;
                long long z = (b - c + 1) % MOD;
                long long vand = x * y % MOD * z % MOD;

                // f^lambda * s_lambda(1,1,1), lambda=(a,b,c)
                long long term = fact[N];
                term = term * vand % MOD * vand % MOD * inv2 % MOD;
                term = term * ifact[a + 2] % MOD;
                term = term * ifact[b + 1] % MOD;
                term = term * ifact[c] % MOD;
                ans += term;
                if (ans >= MOD) ans -= MOD;
            }
        }

        memo[key] = ans;
        cout << ans << '\n';
    }
    return 0;
}
