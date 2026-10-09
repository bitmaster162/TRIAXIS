#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

using P = array<int,3>;

P canon3(array<int,3> a){
    map<int,int> mp; int nx=0;
    for(int i=0;i<3;i++){
        if(!mp.count(a[i])) mp[a[i]]=nx++;
        a[i]=mp[a[i]];
    }
    return a;
}
int enc(P a){
    a=canon3(a);
    if(a==P{0,1,2}) return 0;
    if(a==P{0,0,1}) return 1; // H=F
    if(a==P{0,1,0}) return 2; // H=C
    if(a==P{0,1,1}) return 3; // F=C
    return 4;                 // all
}
P dec(int s){
    if(s==0) return {0,1,2};
    if(s==1) return {0,0,1};
    if(s==2) return {0,1,0};
    if(s==3) return {0,1,1};
    return {0,0,0};
}
struct DSU{
    int p[4];
    DSU(){ iota(p,p+4,0); }
    int f(int x){ return p[x]==x?x:p[x]=f(p[x]); }
    bool unite(int a,int b){
        a=f(a); b=f(b);
        if(a==b) return false;
        p[b]=a; return true;
    }
};
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N; string s;
    if(!(cin>>N>>s)) return 0;
    array<long long,5> dp{}, ndp{};
    // frontier = H,F,C and initially F=C=vertex 0.
    dp[3]=1; // omit spoke 0
    if(s[0]=='1') dp[4]=1; // include spoke 0
    for(int vtx=1; vtx<N; ++vtx){
        ndp.fill(0);
        for(int st=0; st<5; ++st) if(dp[st]){
            P q=dec(st);
            for(int takePath=0; takePath<=1; ++takePath){
                int maxSp = s[vtx]=='1' ? 1 : 0;
                for(int takeSp=0; takeSp<=maxSp; ++takeSp){
                    DSU d;
                    for(int i=0;i<3;i++) for(int j=i+1;j<3;j++)
                        if(q[i]==q[j]) d.unite(i,j);
                    bool ok=true;
                    if(takePath && !d.unite(2,3)) ok=false; // old current - new
                    if(ok && takeSp && !d.unite(0,3)) ok=false; // hub - new
                    if(!ok) continue;
                    int roots[3]={d.f(0),d.f(1),d.f(3)};
                    map<int,int> mp; int nx=0; P nq;
                    for(int i=0;i<3;i++){
                        if(!mp.count(roots[i])) mp[roots[i]]=nx++;
                        nq[i]=mp[roots[i]];
                    }
                    int ns=enc(nq);
                    ndp[ns]=(ndp[ns]+dp[st])%MOD;
                }
            }
        }
        dp=ndp;
    }
    long long ans=0;
    for(int st=0;st<5;st++) if(dp[st]){
        P q=dec(st);
        // closing cycle edge omitted
        ans=(ans+dp[st])%MOD;
        // closing edge included iff F and current are not already connected
        if(q[1]!=q[2]) ans=(ans+dp[st])%MOD;
    }
    cout<<ans%MOD<<"\n";
}
