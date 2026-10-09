#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N;
    if(!(cin>>N)) return 0;
    vector<int> Q(N+1);
    for(int i=1;i<=N;i++) cin>>Q[i];

    if(Q[N]!=-1 && Q[N]!=N){
        cout<<0<<"\n";
        return 0;
    }
    for(int i=1;i<N;i++){
        if(Q[i]==N){
            cout<<0<<"\n";
            return 0;
        }
    }

    int n=N-1;
    vector<int> fixedPos(n+1,-1), isFree(n+2,0), freePref(n+2,0);
    for(int p=1;p<=n;p++){
        if(Q[p]==-1) isFree[p]=1;
        else fixedPos[Q[p]]=p;
    }
    for(int p=1;p<=n;p++) freePref[p]=freePref[p-1]+isFree[p];
    int totalFree=freePref[n];

    vector<long long> dp(n+2),ndp(n+2),suff(n+3);
    dp[n+1]=1;
    int usedUnfixed=0;

    for(int v=n;v>=1;--v){
        suff[n+2]=0;
        for(int m=n+1;m>=1;--m) suff[m]=(suff[m+1]+dp[m])%MOD;
        fill(ndp.begin(),ndp.end(),0);

        int p=fixedPos[v];
        if(p!=-1){
            for(int m=1;m<p;m++) ndp[m]=dp[m];
            ndp[p]=2*suff[p+1]%MOD;
        }else{
            for(int m=1;m<=n+1;m++){
                if(dp[m]==0) continue;
                int freeGt = (m<=n ? totalFree-freePref[m] : 0);
                int usedFreeGt = usedUnfixed - ((m<=n && isFree[m])?1:0);
                int avail=freeGt-usedFreeGt;
                if(avail>0){
                    ndp[m]=(ndp[m]+dp[m]*avail)%MOD;
                }
            }
            for(int p0=1;p0<=n;p0++) if(isFree[p0]){
                ndp[p0]=(ndp[p0]+2*suff[p0+1])%MOD;
            }
            usedUnfixed++;
        }
        dp.swap(ndp);
    }

    cout<<dp[1]%MOD<<"\n";
    return 0;
}
