#include <bits/stdc++.h>
using namespace std;
static const long long MOD = 998244353;
static const int V = 100000;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin >> N)) return 0;
    vector<int> A(N);
    for(int &x : A) cin >> x;

    vector<int> phi(V + 1);
    iota(phi.begin(), phi.end(), 0);
    for(int p = 2; p <= V; ++p){
        if(phi[p] == p){
            for(int x = p; x <= V; x += p){
                phi[x] -= phi[x] / p;
            }
        }
    }

    vector<vector<int>> divisors(V + 1);
    for(int d = 1; d <= V; ++d){
        for(int x = d; x <= V; x += d){
            divisors[x].push_back(d);
        }
    }

    vector<long long> sumDiv(V + 1, 0);
    long long ans = 0;
    long long pow2 = 1; // 2^(i-1) for current 1-indexed i

    for(int i = 0; i < N; ++i){
        long long f = 0;
        for(int d : divisors[A[i]]){
            f = (f + 1LL * phi[d] * sumDiv[d]) % MOD;
        }

        ans = (2 * ans + f) % MOD;
        cout << ans << '\n';

        for(int d : divisors[A[i]]){
            sumDiv[d] += pow2;
            if(sumDiv[d] >= MOD) sumDiv[d] -= MOD;
        }
        pow2 = 2 * pow2 % MOD;
    }
    return 0;
}
