#include <bits/stdc++.h>
using namespace std;
static const int MOD=998244353;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N; if(!(cin>>N)) return 0;
    vector<int>A(N),B(N);
    for(int&i:A) cin>>i;
    for(int&i:B) cin>>i;
    vector<vector<int>> perms;
    vector<int> p(N); iota(p.begin(),p.end(),1);
    do{ perms.push_back(p); }while(next_permutation(p.begin(),p.end()));
    set<vector<int>> seen;
    long long ans=0;
    for(auto &x:perms) for(auto &y:perms) for(auto &z:perms){
        vector<array<int,3>> seq(N);
        vector<tuple<array<int,3>,int,int>> all;
        all.reserve(2*N);
        bool bad=false;
        set<array<int,3>> uniq;
        for(int i=0;i<N;i++){
            seq[i]={x[i],y[i],z[i]};
            array<int,3> rev={z[i],y[i],x[i]};
            if(!uniq.insert(seq[i]).second) bad=true;
            if(!uniq.insert(rev).second) bad=true;
            all.push_back({seq[i],i,0});
            all.push_back({rev,i,1});
        }
        if(bad) continue;
        sort(all.begin(),all.end(),[](auto const&u,auto const&v){ return get<0>(u)<get<0>(v); });
        vector<int>a(N),b(N);
        for(int r=0;r<2*N;r++){
            auto [s,i,t]=all[r];
            if(t==0) a[i]=r+1; else b[i]=r+1;
        }
        bool ok=true;
        for(int i=0;i<N;i++){
            if(a[i]!=A[i]) ok=false;
            if(B[i]!=-1 && b[i]!=B[i]) ok=false;
        }
        if(!ok) continue;
        vector<int> key=a; key.insert(key.end(),b.begin(),b.end());
        if(seen.insert(key).second) ans++;
    }
    cout<<(ans%MOD)<<"\n";
}
