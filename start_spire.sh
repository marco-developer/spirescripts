#/bin/bash

# This script aims to show sample interactions with SPIRE Server and Agent.
# To use run the script and firstly start the spire server, through spire-server management menu.

start_spire_server () {
# # Start the SPIRE Server as a background process
echo "Starting spire-server..."
sleep 1
./spire-server run -config ../conf/server/server.conf &
sleep 3

}

reset_spire() {
    # Stop spire-server and agent processes and delete server data
    kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
    kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
    rm -rf /spire/.data
}

create_spiffeid() {
    echo "Enter the SPIFFE-ID:"
    read spiffeid
    echo "Enter the selector:"
    read selector

    ./spire-server entry create \
        -parentID spiffe://example.org/host \
        -spiffeID spiffe://example.org/$spiffeid \
        -selector $selector
}


oauth2spiffeid() {
    # Receives a Google OAuth token and create a related SPIFFE-ID.
    echo "Enter the Google OAuth Token:"
    read oauthtoken
    echo "Enter the selector:"
    read selector

    tokeninfo=$(curl \
                --request POST \
                --data "access_token=$oauthtoken" \
                https://www.googleapis.com/oauth2/v1/tokeninfo)

    
    read userid < <(echo $tokeninfo | jq -r '.user_id')
    read ttl < <(echo $tokeninfo | jq -r '.expires_in')

    ./spire-server entry create \
        -parentID spiffe://example.org/host \
        -ttl $ttl \
        -spiffeID spiffe://example.org/$userid \
        -selector $selector
}

delete_spiffeid() {
    echo "Enter the Entry ID:"
    read entryid

    ./spire-server entry delete \
        -entryID $entryid
}

list_spiffeids() {
    ./spire-server entry show
}

count_spiffeids() {
    ./spire-server entry count
}

update_spiffeid() {
# Pode atualizar selector entre outras coisas...
     
	list_spiffeids	

	echo "Enter the EntryID:"
	read entryid

	echo "Enter the Selector:"
	read selector

	echo "Enter the ParentID"
	read parentid

	echo "Enter the new SPIFFE-ID:"
	read spiffeid
	

	./spire-server entry update -entryID $entryid -selector $selector -parentID $parentid -spiffeID $spiffeid
	
 }

# mint_JWT() {
#     #nao tenho ideia do que faz... gera um jwt para um spiffeid?
# }

# mint_x509() {
#     #nao tenho ideia do que faz... gera um jwt para um spiffeid?
# }

list_agents() {
    ./spire-server agent list
}

count_agents() {
    ./spire-server agent count
}

generate_jointoken () {
# Generate a one time Join Token. 
# Use the -spiffeID option to associate the Join Token with spiffe://example.org/host SPIFFE ID. 
echo "Generating token..."
sleep 1
tmp=$(./spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
# echo $token >> tokens.lst
echo "$token sucessfuly generated. Ready to start a new agent."
}

start_spire_agent () {

    # Generate a token to a new agent.
    generate_jointoken
    # Start the SPIRE Agent as a background process using the token passed by parameter.
    echo "Starting spire-agent..."
    sleep 1
    ./spire-agent run -config ../conf/agent/agent.conf -joinToken $token &
    sleep 1
    token=''
}

check_spire_server () {
    ./spire-server healthcheck
}

# ban_agent() {
    # echo "Not implemented. :("
# }

evict_agent() {
    echo "Enter the SPIFFE-ID:"
    read spiffeid

    ./spire-server agent evict -spiffeID $spiffeid
}

SPIFFEID2JWT() {

    # usage:
    # ./jwt_gen.sh <parent-id> <aat> <spiffe-id> <dpr>
    echo "Not implemented. :("
    
}

# Simulate the Workload API interaction and retrieve the workload SVID bundle by running the api 
# subcommand in the agent.
# echo "Interagindo com API..."
# sleep 1
# su -c "spire-agent api fetch x509 " workload

# Execution phase:
# start_spire_server
# generate_jointoken
# start_spire_agent $token
# list_agents
# create_spiffeid
# list_spiffeids
# delete_spiffeid

mainmenu() {
    clear
    echo -ne "
MAIN MENU

 1) Spire Server
 2) Spire Agent
 0) Exit
Choose an option:  "
    read -r ans
    case $ans in
    1)
        menu_server
        mainmenu
        ;;
    0)
        echo "Bye bye."
        exit 0
        ;;
    *)
        echo "Wrong option."
        exit 1
        ;;
    esac
}

menu_server() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
SPIRE SERVER

Server status: $status || Number of agents: $agents || Number of registration entries: $entries 

1) Server management
2) Agents
3) Registration Entries
0) Back
Choose an option:  "
    read -r ans
    case $ans in
        1)
            menu_server_mgmt
            ;;
        2)  
            menu_server_agents
            ;;
        3)
            menu_server_spiffeid
            ;;
        0)
            mainmenu
            ;;
        *)
            echo "Wrong option."
            ;;

    esac
}

menu_server_mgmt() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
SPIRE SERVER MANAGEMENT

Server status: $status || Number of agents: $agents || Number of registration entries: $entries 

1) Start
2) Stop and reset all
0) Back
Choose an option:  "
    read -r ans
    case $ans in
        1)
            start_spire_server
            echo "Press any key to continue..."
            read
            clear
            menu_server_mgmt
            ;;
        2)
            reset_spire
            echo "Press any key to continue..."
            read
            clear
            menu_server_mgmt
            ;;
        0)
            menu_server
            ;;
        *)
            echo "Wrong option."
            ;;
    esac
}

menu_server_agents() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
SPIRE SERVER AGENTS

Server status: $status || Number of agents: $agents || Number of registration entries: $entries
Available agent token: $token

1) Start new agent
2) List agents
3) Ban agent
4) Evict agent
0) Back
Choose an option:  "
    read -r ans
    case $ans in
        1)
            start_spire_agent
            echo "Press any key to continue..."
            read
            clear
            menu_server_agents
            ;;
        2)
            list_agents
            echo "Press any key to continue..."
            read
            clear
            menu_server_agents
            ;;
        3)
            ban_agents
            echo "Press any key to continue..."
            read
            clear
            menu_server_agents
            ;;
        4)
            evict_agent
            echo "Press any key to continue..."
            read
            clear
            menu_server_agents
            ;;
        0)
            menu_server
            ;;
        *)  
            echo "Wrong option."
            ;;
    esac
}

menu_server_spiffeid() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
SPIRE SERVER REGISTRATION ENTRIES

Server status: $status || Number of agents: $agents || Number of registration entries: $entries 

1) Create SPIFFE-ID
2) List SPIFFE-IDs
3) Delete SPIFFE-ID
4) Create OAuth2SPIFFE-ID
5) Create SPIFFE-ID2JWT
6) Update SPIFFE-ID
0) Back
Choose an option:  "
    read -r ans
    case $ans in
        1)
            create_spiffeid
            echo "Press any key to continue..."
            read
            clear
            menu_server_spiffeid
            ;;
        2)
            list_spiffeids
            echo "Press any key to continue..."
            read
            clear
            menu_server_spiffeid
            ;;
        3)
            delete_spiffeid
            echo "Press any key to continue..."
            read
            clear
            menu_server_spiffeid
            ;;
        4)
            oauth2spiffeid
            echo "Press any key to continue..."
            read
            clear
            menu_server_spiffeid
            ;;
        5)
            SPIFFEID2JWT
            echo "Press any key to continue..."
            read
            clear
            menu_server_spiffeid
            ;;
	6) 
	    update_spiffeid
	    echo "Press any key to continue..."
	    read
	    clear
	    menu_server_spiffeid
	    ;;
        0)
            menu_server
            ;;
        *)
            echo "Wrong option."
            ;;
    esac
}

mainmenu
