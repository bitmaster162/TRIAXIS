#include <bits/stdc++.h>
using namespace std;

struct Fenwick{
    int n; vector<int> bit;
    Fenwick(int n):n(n),bit(n+1,0){}
    void add(int i,int v){ for(;i<=n;i+=i&-i) bit[i]+=v; }
    int sum(int i)const{ int s=0; for(;i>0;i-=i&-i) s+=bit[i]; return s; }
};
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N;
    if(!(cin>>N)) return 0;
    vector<int>P(N+1),pos(N+1);
    for(int i=1;i<=N;i++){cin>>P[i]; pos[P[i]]=i;}
    Fenwick fw(N);
    long long ans=0;
    for(int k=1;k<=N;k++){
        fw.add(pos[k],1);
        long long p=fw.sum(pos[k]); // position of k after deleting values > k
        long long d=k-p;
        ans += d*(p + k - 1)/2;
    }
    cout<<ans<<"\n";
    return 0;
}
