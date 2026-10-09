#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

long long modpow(long long a,long long e){
    long long r=1;
    while(e){ if(e&1) r=r*a%MOD; a=a*a%MOD; e>>=1; }
    return r;
}
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N; string S;
    if(!(cin>>N>>S)) return 0;
    vector<int> lev(N/2+2,0);
    int h=0,maxd=0;
    for(char c:S){
        if(c=='('){
            lev[h]++;
            maxd=max(maxd,h);
            h++;
        }else h--;
    }
    int M=N+5;
    vector<long long> fac(M),ifac(M);
    fac[0]=1;
    for(int i=1;i<M;i++) fac[i]=fac[i-1]*i%MOD;
    ifac[M-1]=modpow(fac[M-1],MOD-2);
    for(int i=M-1;i>=1;i--) ifac[i-1]=ifac[i]*i%MOD;
    auto C=[&](int n,int r)->long long{
        if(r<0||r>n||n<0) return 0;
        return fac[n]*ifac[r]%MOD*ifac[n-r]%MOD;
    };
    long long ans=1;
    for(int d=0;d<=maxd;d++){
        int a=lev[d];
        int b=lev[d+1];
        if(b==0) continue;
        if(a==0){ cout<<0<<"\n"; return 0; }
        ans=ans*C(a+b-1,b)%MOD;
    }
    cout<<ans<<"\n";
    return 0;
}
