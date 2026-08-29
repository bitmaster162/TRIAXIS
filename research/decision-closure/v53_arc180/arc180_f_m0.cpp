#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int64 MOD = 1000000007LL;

static int64 modpow(int64 a, int64 e){
    int64 r=1;
    while(e){
        if(e&1) r=(__int128)r*a%MOD;
        a=(__int128)a*a%MOD;
        e>>=1;
    }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N, A;
    if(!(cin>>N>>A)) return 0;

    vector<int64> inv(max(2,N+1),1);
    for(int i=2;i<=N;i++) inv[i]=MOD-(MOD/i)*inv[MOD%i]%MOD;

    vector<int64> dp(1,1); // after integrating x_1
    for(int k=2;k<=N;k++){
        vector<int64> q(k,0), ndp(k,0);
        for(int r=0;r<(int)dp.size();r++){
            int avail=k-1-r;
            int64 comb=1;
            for(int d=0;d<=avail;d++){
                int c=r+d;
                q[c]=(q[c]+(__int128)dp[r]*comb)%MOD;
                if(d<avail){
                    comb=(__int128)comb*(avail-d)%MOD*inv[d+1]%MOD;
                }
            }
        }
        for(int c=0;c<k;c++){
            int64 den=(k+(int64)A*c)%MOD;
            ndp[c]=(__int128)q[c]*modpow(den,MOD-2)%MOD;
        }
        dp.swap(ndp);
    }

    int64 ans=0;
    for(auto x:dp) ans+=x, ans%=MOD;
    for(int i=2;i<=N;i++) ans=(__int128)ans*i%MOD;
    cout<<ans<<"\n";
    return 0;
}
