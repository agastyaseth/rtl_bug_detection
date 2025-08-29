// CWE: CWE-441
module confused_deputy_example #(parameter DATA_WIDTH = 32, parameter ADDR_WIDTH = 8)
(
    input wire clk,
    input wire reset_n,
    
    input wire user_request,
    input wire [ADDR_WIDTH-1:0] user_address,
    input wire [DATA_WIDTH-1:0] user_data,
    output reg [DATA_WIDTH-1:0] user_response,
    
    input wire admin_request,
    input wire [ADDR_WIDTH-1:0] admin_address,
    input wire [DATA_WIDTH-1:0] admin_data,
    output reg [DATA_WIDTH-1:0] admin_response
);

reg [DATA_WIDTH-1:0] memory [0:(1<<ADDR_WIDTH)-1];
reg [ADDR_WIDTH-1:0] current_address;
reg [DATA_WIDTH-1:0] current_data;
reg is_admin;

// Memory access logic
always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
        current_address <= {ADDR_WIDTH{1'b0}};
        current_data <= {DATA_WIDTH{1'b0}};
        is_admin <= 1'b0;
    end else begin
        if (admin_request) begin
            current_address <= admin_address;
            current_data <= admin_data;
            is_admin <= 1'b1;
        end else if (user_request) begin
            current_address <= user_address;
            current_data <= user_data;
            is_admin <= 1'b0;
        end
        
        // Confused deputy vulnerability: user can write to admin memory space
        if (is_admin || user_request) begin
            memory[current_address] <= current_data;
        end
    end
end

// Response logic
always @(*) begin
    if (admin_request) begin
        admin_response = memory[admin_address];
    end else if (user_request) begin
        user_response = memory[user_address];
    end
end

endmodule