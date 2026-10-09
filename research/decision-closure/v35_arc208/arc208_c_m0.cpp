#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T; cin >> T;
    while(T--){
        long long C,X; cin >> C >> X;
        long long n0 = (C ^ X);
        if(n0 > X){
            cout << n0 << '\n';
            continue;
        }
        bool ok=false;
        long long ans=-1;
        if(C>=X && ((C-X)&1LL)==0){
            long long s=(C-X)/2;
            if((s & ~C)==0){
                long long n=(1LL<<30)+s;
                if(n>X && n<(1LL<<60)){
                    ans=n; ok=true;
                }
            }
        }
        cout << (ok?ans:-1) << '\n';
    }
    return 0;
}
