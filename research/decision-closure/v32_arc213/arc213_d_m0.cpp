#include <bits/stdc++.h>
using namespace std;
using ll = long long;
const ll MOD=998244353;

ll modpow(ll a,ll e){
    ll r=1;
    while(e){ if(e&1) r=r*a%MOD; a=a*a%MOD; e>>=1; }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N,K; cin>>N>>K;
    vector<ll> fac(N+1),ifac(N+1),inv(N+1);
    fac[0]=1;
    for(int i=1;i<=N;++i) fac[i]=fac[i-1]*i%MOD;
    ifac[N]=modpow(fac[N],MOD-2);
    for(int i=N;i>=1;--i) ifac[i-1]=ifac[i]*i%MOD;
    for(int i=1;i<=N;++i) inv[i]=fac[i-1]*ifac[i]%MOD;
    auto C=[&](int n,int r)->ll{
        if(r<0||r>n) return 0;
        return fac[n]*ifac[r]%MOD*ifac[n-r]%MOD;
    };

    int A=K-1, B=N-K;
    vector<ll> H(N+1), J(N+1), U(N+1), W(N+2);
    for(int v=1;v<=N;++v){
        ll n=v-1;
        H[v]=((n*n)/4)%MOD;
        ll num=0;
        int lo=max(0,(int)n-B), hi=min(A,(int)n);
        for(int x=lo;x<=hi;++x){
            ll h=min<ll>(x,n-x)%MOD;
            num=(num+h*C(A,x)%MOD*C(B,(int)n-x))%MOD;
        }
        ll den=C(N-1,(int)n);
        J[v]=num*modpow(den,MOD-2)%MOD;
        U[v]=H[v]*inv[v]%MOD;
        if(v>=2){
            W[v]=(H[v]-J[v]+MOD)%MOD*inv[v-1]%MOD;
        }
    }

    vector<ll> pre(N+1), suf(N+2);
    for(int v=1;v<=N;++v) pre[v]=(pre[v-1]+U[v])%MOD;
    for(int v=N;v>=1;--v) suf[v]=(suf[v+1]+W[v])%MOD;

    ll total=fac[N-1];
    for(int a=1;a<=N;++a){
        ll e=(pre[a-1]+suf[a+1]+J[a])%MOD;
        cout << total*e%MOD << '\n';
    }
    return 0;
}
