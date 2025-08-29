// CWE: CWE-441
module unintended_proxy #(parameter DATA_WIDTH = 32, parameter ADDR_WIDTH = 8)
(
    input wire clk,
    input wire reset_n,
    input wire start,
    output wire ready,

    input wire [ADDR_WIDTH-1:0] address,
    input wire [DATA_WIDTH-1:0] write_data,
    input wire write_enable,
    output wire [DATA_WIDTH-1:0] read_data,

    input wire [DATA_WIDTH-1:0] proxy_data,
    input wire proxy_enable
);

    reg [DATA_WIDTH-1:0] memory [0:(1<<ADDR_WIDTH)-1];
    reg [DATA_WIDTH-1:0] read_data_reg;
    reg ready_reg;

    assign read_data = read_data_reg;
    assign ready = ready_reg;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            ready_reg <= 1'b0;
        end else begin
            if (start) begin
                ready_reg <= 1'b0;
                if (write_enable) begin
                    memory[address] <= write_data;
                end
                read_data_reg <= memory[address];
                ready_reg <= 1'b1;
            end
        end
    end

    always @(posedge clk) begin
        if (proxy_enable) begin
            memory[address] <= proxy_data; // Unintended proxy write
        end
    end

endmodule