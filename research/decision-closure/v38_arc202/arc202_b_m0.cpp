#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int MOD = 998244353;

int64 modpow(int64 a, int64 e){
    int64 r=1;
    while(e){ if(e&1) r=r*a%MOD; a=a*a%MOD; e>>=1; }
    return r;
}
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int H,W;
    if(!(cin>>H>>W)) return 0;
    if(H%2==0){ cout<<0<<"\n"; return 0; }

    int nmax = (W%2 ? H : 2*H);
    vector<int64> fac(nmax+1), ifac(nmax+1);
    fac[0]=1;
    for(int i=1;i<=nmax;i++) fac[i]=fac[i-1]*i%MOD;
    ifac[nmax]=modpow(fac[nmax],MOD-2);
    for(int i=nmax;i>=1;i--) ifac[i-1]=ifac[i]*i%MOD;
    auto C=[&](int n,int r)->int64{
        if(r<0||r>n) return 0;
        return fac[n]*ifac[r]%MOD*ifac[n-r]%MOD;
    };

    int64 ans=0;
    if(W%2){
        for(int p=0;p<=H;p++){
            int s=2*p-H;
            if(std::gcd(abs(s),W)==1){
                ans += C(H,p);
                if(ans>=MOD) ans-=MOD;
            }
        }
    }else{
        int M=W/2;
        for(int s=-H;s<=H;s++){
            if(std::gcd(abs(s),M)==1){
                ans += C(2*H,H+s);
                if(ans>=MOD) ans-=MOD;
            }
        }
    }
    cout<<ans%MOD<<"\n";
    return 0;
}
