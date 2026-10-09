#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N,K;
    if(!(cin>>N>>K)) return 0;
    int M=N*K;
    vector<int>P(M);
    for(int&i:P){cin>>i;--i;}
    vector<char>vis(M,0);
    long long ans=0;
    for(int s=0;s<M;s++) if(!vis[s]){
        vector<int> cyc;
        int v=s;
        while(!vis[v]){
            vis[v]=1;
            cyc.push_back(v);
            v=P[v];
        }
        vector<char> seen(N,0);
        int d=0;
        for(int x:cyc){
            int r=x%N;
            if(!seen[r]) seen[r]=1,++d;
        }
        ans += (int)cyc.size()-d;
    }
    cout<<ans<<"\n";
}
