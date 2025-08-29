// CWE: CWE-1272
module encryption_core(
    input wire clk,
    input wire rst,
    input wire start,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output wire [127:0] ciphertext,
    output wire done
);

// Internal signals
reg [127:0] key_reg;
reg [127:0] plaintext_reg;
reg [127:0] ciphertext_reg;
reg done_reg;
reg [3:0] state;
reg [3:0] next_state;

// State encoding
localparam IDLE = 4'd0;
localparam LOAD = 4'd1;
localparam ENCRYPT = 4'd2;
localparam FINISH = 4'd3;

// Output assignments
assign ciphertext = ciphertext_reg;
assign done = done_reg;

// State transition
always @(posedge clk or posedge rst) begin
    if (rst) begin
        state <= IDLE;
    end else begin
        state <= next_state;
    end
end

// Next state logic
always @* begin
    next_state = state;
    case (state)
        IDLE: begin
            if (start) begin
                next_state = LOAD;
            end
        end
        LOAD: begin
            next_state = ENCRYPT;
        end
        ENCRYPT: begin
            next_state = FINISH;
        end
        FINISH: begin
            next_state = IDLE;
        end
    endcase
end

// Output logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        key_reg <= 128'd0;
        plaintext_reg <= 128'd0;
        ciphertext_reg <= 128'd0;
        done_reg <= 1'b0;
    end else begin
        case (state)
            LOAD: begin
                key_reg <= key;
                plaintext_reg <= plaintext;
            end
            ENCRYPT: begin
                // Simple XOR encryption for demonstration
                ciphertext_reg <= plaintext_reg ^ key_reg;
            end
            FINISH: begin
                done_reg <= 1'b1;
            end
            default: begin
                done_reg <= 1'b0;
            end
        endcase
    end
end

endmodule