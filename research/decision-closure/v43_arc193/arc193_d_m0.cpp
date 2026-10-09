#include <bits/stdc++.h>
using namespace std;
struct VH{
    size_t operator()(vector<int> const& a) const noexcept{
        uint64_t h=1469598103934665603ULL;
        for(int x:a){ h^=(uint32_t)x+0x9e3779b9; h*=1099511628211ULL; }
        return (size_t)h;
    }
};
static bool goal(vector<int> const& p, string const& B){
    vector<char> occ(B.size()+1,0);
    for(int x:p) occ[x]=1;
    for(int i=1;i<=(int)B.size();i++)
        if((occ[i]?1:0)!=(B[i-1]-'0')) return false;
    return true;
}
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T; cin>>T;
    while(T--){
        int N; string A,B; cin>>N>>A>>B;
        vector<int> start;
        for(int i=0;i<N;i++) if(A[i]=='1') start.push_back(i+1);
        int need=count(B.begin(),B.end(),'1');
        if(need>(int)start.size()){ cout<<-1<<"\n"; continue; }
        if(goal(start,B)){ cout<<0<<"\n"; continue; }
        unordered_map<vector<int>,int,VH> dist;
        queue<vector<int>> q;
        dist[start]=0; q.push(start);
        int answer=-1;
        while(!q.empty() && answer==-1){
            vector<int> cur=move(q.front()); q.pop();
            int cd=dist[cur];
            for(int t=1;t<=N;t++){
                vector<int> nx=cur;
                for(int &x:nx){
                    if(x<t) ++x;
                    else if(x>t) --x;
                }
                // order stays nondecreasing
                if(dist.emplace(nx,cd+1).second){
                    if(goal(nx,B)){ answer=cd+1; break; }
                    q.push(move(nx));
                }
            }
        }
        cout<<answer<<"\n";
    }
}
