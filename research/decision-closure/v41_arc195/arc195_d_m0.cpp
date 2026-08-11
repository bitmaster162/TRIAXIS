#include <bits/stdc++.h>
using namespace std;

long long inversion_distance_stable(const vector<int>& orig, const vector<int>& target){
    unordered_map<int, vector<int>> pos;
    pos.reserve(orig.size()*2+1);
    for(int i=0;i<(int)orig.size();i++) pos[orig[i]].push_back(i);
    unordered_map<int,int> ptr;
    ptr.reserve(pos.size()*2+1);
    vector<int> idx;
    idx.reserve(orig.size());
    for(int x: target){
        int &p=ptr[x];
        idx.push_back(pos[x][p++]);
    }
    long long inv=0;
    for(int i=0;i<(int)idx.size();i++)
        for(int j=i+1;j<(int)idx.size();j++)
            inv += idx[i]>idx[j];
    return inv;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T;
    cin>>T;
    while(T--){
        int N;
        cin>>N;
        vector<int>A(N);
        for(int&i:A) cin>>i;
        vector<int> p=A;
        sort(p.begin(),p.end());
        long long ans=(1LL<<60);
        do{
            long long inv=inversion_distance_stable(A,p);
            int runs=1;
            for(int i=1;i<N;i++) runs += p[i]!=p[i-1];
            ans=min(ans,inv+runs);
        }while(next_permutation(p.begin(),p.end()));
        cout<<ans<<"\n";
    }
    return 0;
}
