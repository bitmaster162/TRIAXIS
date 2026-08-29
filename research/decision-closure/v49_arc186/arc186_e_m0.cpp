#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

long long modpow(long long a,long long e){
    long long r=1;
    while(e){
        if(e&1) r=r*a%MOD;
        a=a*a%MOD;
        e>>=1;
    }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,M,K;
    if(!(cin>>N>>M>>K)) return 0;
    vector<int>X(M);
    for(int &x:X) cin>>x;

    int transitions=0;
    for(int i=0;i+1<M;i++) transitions += (X[i]!=X[i+1]);

    long long minLen = 1LL*M*K - 1 + transitions;
    if(minLen > N){
        cout << 0 << '\n';
        return 0;
    }
    int S = N - (int)minLen;
    int q=K-1;

    // f[l] = number of length-l words over q symbols containing every symbol.
    // Inclusion-exclusion: sum_j (-1)^j C(q,j) (q-j)^l.
    vector<long long> comb(q+1), pw(q+1,1), f(N+1), g(N+1);
    comb[0]=1;
    for(int j=1;j<=q;j++){
        comb[j]=comb[j-1]*(q-j+1)%MOD*modpow(j,MOD-2)%MOD;
    }
    for(int l=0;l<=N;l++){
        long long s=0;
        for(int j=0;j<=q;j++){
            long long term=comb[j]*pw[j]%MOD;
            if(j&1) s=(s-term+MOD)%MOD;
            else s=(s+term)%MOD;
        }
        f[l]=s;
        for(int j=0;j<=q;j++) pw[j]=pw[j]*(q-j)%MOD;
    }

    // For a transition x_t != x_{t+1}, the block must be surjective
    // and have a distinguished x_{t+1} occurring after its first full cover.
    // If p is its final occurrence, the prefix before p is surjective and
    // the suffix after p uses only the other q-1 symbols.
    // Hence g[l] = f[l-1] + (q-1)g[l-1].
    for(int l=1;l<=N;l++){
        g[l]=(f[l-1] + 1LL*(q-1)*g[l-1])%MOD;
    }

    vector<long long> dp(S+1), ndp(S+1);
    dp[0]=1;
    for(int t=0;t<M;t++){
        bool change = (t+1<M && X[t]!=X[t+1]);
        int base = q + (change?1:0);
        fill(ndp.begin(),ndp.end(),0);
        for(int used=0;used<=S;used++) if(dp[used]){
            for(int ex=0;used+ex<=S;ex++){
                int len=base+ex;
                long long ways = change ? g[len] : f[len];
                ndp[used+ex]=(ndp[used+ex] + dp[used]*ways)%MOD;
            }
        }
        dp.swap(ndp);
    }
    cout << dp[S] << '\n';
    return 0;
}
