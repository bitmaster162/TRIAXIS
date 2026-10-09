#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    while(T--){
        long long N, M;
        cin >> N >> M;
        __int128 prod = (__int128)N * (N + 1);
        long long r = (long long)(prod % M);
        cout << ((1 <= r && r <= N) ? "Bob" : "Alice") << '\n';
    }
    return 0;
}
