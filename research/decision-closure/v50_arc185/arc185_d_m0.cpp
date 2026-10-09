#include <bits/stdc++.h>
using namespace std;
static const long long MOD = 998244353;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N, M;
    if(!(cin >> N >> M)) return 0;

    vector<long long> inv(N + 1);
    if(N >= 1) inv[1] = 1;
    for(int i = 2; i <= N; ++i){
        inv[i] = MOD - (MOD / i) * inv[MOD % i] % MOD;
    }

    long long H = 0;
    for(int i = 1; i <= N; ++i){
        H += inv[i];
        if(H >= MOD) H -= MOD;
    }

    long long mm = 1LL * M * M % MOD;
    long long factor = (2LL * N % MOD) * H % MOD;
    factor = (factor - 1 + MOD) % MOD;
    cout << mm * factor % MOD << '\n';
    return 0;
}
