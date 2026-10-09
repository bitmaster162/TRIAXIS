#include <bits/stdc++.h>
using namespace std;

pair<vector<int>,vector<int>> signature(const string& s,int X,int Y){
    vector<int> zsig,osig;
    long long z=0,o=0;
    zsig.reserve(s.size()); osig.reserve(s.size());
    for(char c:s){
        if(c=='0'){
            zsig.push_back((int)(o%Y));
            z++;
        }else{
            osig.push_back((int)(z%X));
            o++;
        }
    }
    return {move(zsig),move(osig)};
}
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N,X,Y; string S,T;
    if(!(cin>>N>>X>>Y>>S>>T)) return 0;
    if(count(S.begin(),S.end(),'0')!=count(T.begin(),T.end(),'0')){
        cout<<"No\n"; return 0;
    }
    auto a=signature(S,X,Y);
    auto b=signature(T,X,Y);
    cout<<((a==b)?"Yes":"No")<<"\n";
    return 0;
}
