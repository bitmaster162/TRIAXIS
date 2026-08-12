#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

struct Group{
    int P=1;
    long long total=0;
    long long sumx=0;
    vector<int> cnt;
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,M;
    if(!(cin>>N>>M)) return 0;

    unordered_map<string,int> id;
    id.reserve((size_t)N*2+10);
    vector<Group> groups;
    long long ans=0;

    for(int row=0;row<N;row++){
        string u(M,'\0');
        for(int j=0;j<M;j++){
            int b; cin>>b; u[j]=(char)b;
        }

        int r=0;
        while(r<M && u[r]==0) r++;
        int x=0, P=1;
        if(r<M){
            int L=M-r;
            while(P<L) P<<=1;
            for(int d=1;d<L;d<<=1){
                if(u[r+d]){
                    x|=d;
                    for(int k=L-1;k>=d;k--){
                        u[r+k]^=u[r+k-d];
                    }
                }
            }
        }

        auto it=id.find(u);
        int gidx;
        if(it==id.end()){
            gidx=(int)groups.size();
            id.emplace(u,gidx);
            Group g;
            g.P=P;
            g.cnt.assign(P,0);
            groups.push_back(std::move(g));
        }else gidx=it->second;

        Group &g=groups[gidx];
        long long greater=0;
        for(int v=x+1;v<g.P;v++) greater+=g.cnt[v];

        __int128 contrib=(__int128)x*g.total - g.sumx + (__int128)g.P*greater;
        long long add=(long long)(contrib%MOD);
        if(add<0) add+=MOD;
        ans+=add;
        if(ans>=MOD) ans-=MOD;

        g.total++;
        g.sumx+=x;
        g.cnt[x]++;
    }

    cout<<ans%MOD<<'\n';
    return 0;
}
