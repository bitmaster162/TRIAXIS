#include <bits/stdc++.h>
using namespace std;
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N; if(!(cin>>N)) return 0;
    vector<int>a(2*N);
    for(int i=0;i<N;i++) cin>>a[i];
    vector<int> target(2*N);
    for(int i=N;i<2*N;i++) target[i]=i-N+1;
    long long t=0;
    while(a!=target){
        vector<int> pos(N+1,-1);
        for(int i=0;i<2*N;i++) if(a[i]>0) pos[a[i]]=i;
        vector<int> nxt(2*N,-1);
        vector<char> used(2*N,0);
        for(int w=N;w>=1;--w){
            int i=pos[w];
            if(used[i]) continue;
            if(i+1<2*N && !used[i+1] && a[i+1]<w){
                nxt[i]=a[i+1]; nxt[i+1]=w;
                used[i]=used[i+1]=1;
            }else{
                nxt[i]=w; used[i]=1;
            }
        }
        for(int i=0;i<2*N;i++) if(!used[i]) nxt[i]=a[i];
        a.swap(nxt); ++t;
    }
    cout<<t<<"\n";
}
