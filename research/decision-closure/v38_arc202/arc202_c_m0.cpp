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

    int N; cin>>N;
    vector<int> A(N);
    int M=1;
    for(int &x:A){ cin>>x; M=max(M,x); }

    const int64 inv9 = modpow(9,MOD-2);
    vector<int64> rep(M+1,1), phi(M+1,1);
    int64 p10=1;
    for(int n=1;n<=M;n++){
        p10=p10*10%MOD;
        rep[n]=(p10-1+MOD)%MOD*inv9%MOD;
        if(n>=2) phi[n]=rep[n];
    }

    for(int d=2;d<=M;d++){
        int64 inv=modpow(phi[d],MOD-2);
        for(int m=d+d;m<=M;m+=d) phi[m]=phi[m]*inv%MOD;
    }

    vector<int> spf(M+1);
    iota(spf.begin(),spf.end(),0);
    for(int i=2;1LL*i*i<=M;i++) if(spf[i]==i)
        for(int j=i*i;j<=M;j+=i) if(spf[j]==j) spf[j]=i;

    vector<char> active(M+1,false);
    int64 cur=1;
    for(int a:A){
        int x=a;
        vector<pair<int,int>> fs;
        while(x>1){
            int p=spf[x], e=0;
            while(x%p==0){ x/=p; ++e; }
            fs.push_back({p,e});
        }
        vector<int> divs{1};
        for(auto [p,e]:fs){
            int sz=divs.size();
            int mul=1;
            for(int k=1;k<=e;k++){
                mul*=p;
                for(int i=0;i<sz;i++) divs.push_back(divs[i]*mul);
            }
        }
        for(int d:divs) if(d>1 && !active[d]){
            active[d]=true;
            cur=cur*phi[d]%MOD;
        }
        cout<<cur<<"\n";
    }
    return 0;
}
