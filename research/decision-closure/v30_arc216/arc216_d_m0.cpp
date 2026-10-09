#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

long long mod_pow(long long a,long long e){ long long r=1%MOD; a%=MOD; while(e){ if(e&1) r=r*a%MOD; a=a*a%MOD; e>>=1;} return r; }
long long egcd(long long a,long long b,long long &x,long long &y){ if(!b){x=1;y=0;return a;} long long x1,y1; long long g=egcd(b,a%b,x1,y1); x=y1; y=x1-y1*(a/b); return g; }
long long inv_mod_int(long long a,long long m){ long long x,y; long long g=egcd(a,m,x,y); if(g!=1) return -1; x%=m; if(x<0)x+=m; return x; }

vector<pair<int,int>> factorize(int x){
    vector<pair<int,int>> f;
    for(int p=2;1LL*p*p<=x;p+=(p==2?1:2)) if(x%p==0){ int e=0; while(x%p==0){x/=p;++e;} f.push_back({p,e}); }
    if(x>1) f.push_back({x,1});
    return f;
}
long long vp_fact(int n,int p){ long long e=0; while(n){ n/=p; e+=n; } return e; }

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    const int MAXN=1000000;
    vector<long long> fact(MAXN+1,1);
    for(int i=1;i<=MAXN;i++) fact[i]=fact[i-1]*i%MOD;

    int T; cin>>T;
    while(T--){
        int N,B,C,D; cin>>N>>B>>C>>D;
        int g=std::gcd(std::gcd(B,C),D);
        int b=B/g, c=C/g, d=D/g;

        long long ans=mod_pow(g,N)*fact[N]%MOD;

        auto fd=factorize(d);
        unordered_set<int> primes_d;
        for(auto [p,e]:fd){
            primes_d.insert(p);
            long long olde=vp_fact(N,p);
            ans = ans * mod_pow(mod_pow(p,olde), MOD-2) % MOD;
        }

        auto fb=factorize(b);
        for(auto [p,bval]:fb){
            if(primes_d.count(p)) continue; // impossible after primitive reduction in the relevant branch, kept defensive.
            long long olde=vp_fact(N,p);

            long long h=1;
            for(int i=0;i<bval;i++) h*=p;
            long long dinv=inv_mod_int(d%h,h);
            long long rh;
            if(h==1) rh=0;
            else {
                long long cm=c%h;
                rh = ((h-cm)%h) * dinv % h;
            }

            long long newe=0;
            long long q=1;
            for(int e=1;;e++){
                if(q > (long long)(N+h)/p + 1 && e>bval+1) break;
                q*=p;
                long long cnt=0;
                if(e<=bval){
                    long long r=rh%q;
                    if(r<N) cnt=1+(N-1-r)/q;
                }else{
                    long long rmax=q-h+rh;
                    if(rmax<N) cnt=1+(N-1-rmax)/q;
                }
                newe+=cnt;
                if(e>bval && q>N+h && cnt==0) break;
            }
            long long delta=newe-olde;
            if(delta>=0) ans=ans*mod_pow(p,delta)%MOD;
            else ans=ans*mod_pow(mod_pow(p,-delta),MOD-2)%MOD;
        }

        cout<<ans%MOD<<'\n';
    }
    return 0;
}
