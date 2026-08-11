#include <bits/stdc++.h>
using namespace std;

static int mex2(int a, bool ha, int b, bool hb){
    bool seen[3]={false,false,false};
    if(ha && 0<=a && a<3) seen[a]=true;
    if(hb && 0<=b && b<3) seen[b]=true;
    for(int x=0;x<3;x++) if(!seen[x]) return x;
    return 3;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T; cin>>T;
    while(T--){
        int N; long long X,Y;
        cin>>N>>X>>Y;
        vector<long long>A(N);
        for(auto &a:A) cin>>a;
        vector<pair<long long,int>> ord;
        ord.reserve(N);
        for(int i=0;i<N;i++) ord.push_back({A[i],i});
        sort(ord.begin(),ord.end());
        vector<int> gans(N,0);
        long long cur=0;
        int gm2=0, gm1=0;
        for(auto [target,idx]:ord){
            while(cur<target){
                long long n=cur+1;
                bool allow1 = ((n-1)%X!=0 && (n-1)%Y!=0);
                bool allow2 = false;
                if(n>=2) allow2 = ((n-2)%X!=0 && (n-2)%Y!=0);
                int gn=mex2(gm1,allow1,gm2,allow2);
                gm2=gm1;
                gm1=gn;
                cur=n;
            }
            gans[idx]=gm1;
        }
        int xr=0;
        for(int g:gans) xr^=g;
        cout<<(xr?"Alice":"Bob")<<'\n';
    }
    return 0;
}
