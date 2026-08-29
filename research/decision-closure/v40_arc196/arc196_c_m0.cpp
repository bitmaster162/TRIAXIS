#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N; string S; if(!(cin>>N)) return 0; cin>>S;
    vector<long long> dp(N+2), ndp(N+2);
    dp[0]=1;
    int w=0,b=0;
    for(int idx=0; idx<2*N; ++idx){
        fill(ndp.begin(),ndp.end(),0);
        if(S[idx]=='B'){
            int d=w-b;
            for(int p=0;p<=b;p++) if(dp[p]){
                ndp[p+1]=(ndp[p+1]+dp[p])%MOD;
                long long r=d+p;
                if(r>0) ndp[p]=(ndp[p]+dp[p]*r)%MOD;
            }
            ++b;
        }else{
            for(int p=0;p<=b;p++) if(dp[p]){
                ndp[p]=(ndp[p]+dp[p])%MOD;
                if(p>0) ndp[p-1]=(ndp[p-1]+dp[p]*p)%MOD;
            }
            ++w;
        }
        if(idx+1<2*N) ndp[0]=0;
        dp.swap(ndp);
    }
    cout<<dp[0]%MOD<<'\n';
}
